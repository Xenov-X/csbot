package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/xenov-x/csbot/config"
	"github.com/xenov-x/csbot/logger"
	"github.com/xenov-x/csbot/output"
	"github.com/xenov-x/csbot/selector"
	"github.com/xenov-x/csbot/workflow"
	csclient "github.com/xenov-x/csrest"
)

func main() {
	var (
		workflowFile = flag.String("workflow", "workflow.yaml", "Path to workflow YAML file")
		configFile   = flag.String("config", "", "Path to configuration YAML file (optional)")
		host         = flag.String("host", "", "Cobalt Strike host (overrides config)")
		port         = flag.Int("port", 0, "Cobalt Strike API port (overrides config)")
		username     = flag.String("username", "", "Username for authentication (overrides config)")
		password     = flag.String("password", "", "Password for authentication (overrides config)")
		insecure     = flag.Bool("insecure", false, "Skip TLS verification (overrides config)")
		logLevel     = flag.String("log-level", "", "Log level: debug, info, warn, error (overrides config)")
		outputFormat = flag.String("output", "text", "Output format: text, json, or csv")
		outputFile   = flag.String("output-file", "", "Write output to file instead of stdout")
		dryRun       = flag.Bool("dry-run", false, "Validate and show what would execute without running")
	)

	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// CLI flags override config file and environment variables
	if *host != "" {
		cfg.Server.Host = *host
	}
	if *port != 0 {
		cfg.Server.Port = *port
	}
	if *username != "" {
		cfg.Server.Username = *username
	}
	if *password != "" {
		cfg.Server.Password = *password
	}
	if *insecure {
		cfg.Server.Insecure = *insecure
	}
	if *logLevel != "" {
		cfg.Logging.Level = *logLevel
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log, err := logger.New(cfg.Logging.Level, cfg.Logging.JSONFormat, cfg.Logging.File)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	log.Info("Starting Cobalt Strike automation bot")

	// Read workflow configuration
	wf, err := workflow.LoadWorkflow(*workflowFile)
	if err != nil {
		log.Error("Failed to load workflow: %v", err)
		os.Exit(1)
	}
	log.Info("Loaded workflow: %s", wf.Name)

	// Create custom HTTP client with TLS config
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Server.Insecure,
		},
	}

	// Configure proxy if specified
	if cfg.Server.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Server.Proxy)
		if err != nil {
			log.Error("Invalid proxy URL: %v", err)
			os.Exit(1)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
		log.Info("Using proxy: %s", cfg.Server.Proxy)
	}

	httpClient := &http.Client{
		Timeout:   time.Duration(cfg.Timeouts.HTTPTimeout) * time.Second,
		Transport: transport,
	}

	// Create API client for authentication and beacon selection
	client := csclient.NewClient(cfg.Server.Host, cfg.Server.Port)
	client.SetHTTPClient(httpClient)

	ctx := context.Background()

	// Skip authentication in dry-run mode
	if !*dryRun {
		// Authenticate
		log.Info("Authenticating as %s...", cfg.Server.Username)
		_, err = client.Login(ctx, cfg.Server.Username, cfg.Server.Password, 3600000) // 1 hour
		if err != nil {
			log.Error("Authentication failed: %v", err)
			os.Exit(1)
		}
		log.Info("Authentication successful")
	} else {
		log.Info("Skipping authentication in dry-run mode")
	}

	// Validate workflow (skip beacon check in dry-run mode)
	log.Info("Validating workflow...")
	var validatorClient *csclient.Client
	if !*dryRun {
		validatorClient = client
	}
	validator := workflow.NewValidator(validatorClient)
	validationErrors := validator.Validate(ctx, wf)

	hasErrors := false
	for _, valErr := range validationErrors {
		if valErr.Severity == "warning" {
			log.Warn("[%s] %s", valErr.Type, valErr.Message)
		} else {
			log.Error("[%s] %s", valErr.Type, valErr.Message)
			hasErrors = true
		}
	}

	if hasErrors {
		log.Error("Workflow validation failed with errors")
		os.Exit(1)
	}

	if len(validationErrors) == 0 {
		log.Info("Workflow validation passed")
	} else {
		log.Info("Workflow validation passed with warnings")
	}

	// If dry-run mode, show what would execute and exit
	if *dryRun {
		log.Info("=== DRY RUN MODE ===")
		log.Info("Workflow would execute the following actions:")
		fmt.Println()
		for i, action := range wf.Actions {
			fmt.Printf("[%d] %s (%s)\n", i+1, action.Name, action.Type)
			if len(action.Parameters) > 0 {
				fmt.Println("    Parameters:")
				for key, val := range action.Parameters {
					fmt.Printf("      - %s: %v\n", key, val)
				}
			}
			if len(action.Conditions) > 0 {
				fmt.Println("    Conditions:")
				for _, cond := range action.Conditions {
					fmt.Printf("      - %s %s '%s'\n", cond.Source, cond.Operator, cond.Value)
				}
			}
			if len(action.OnSuccess) > 0 {
				fmt.Printf("    On Success: %d actions\n", len(action.OnSuccess))
			}
			if len(action.OnFailure) > 0 {
				fmt.Printf("    On Failure: %d actions\n", len(action.OnFailure))
			}
			fmt.Println()
		}
		if wf.Parallel {
			log.Info("NOTE: Actions would execute in PARALLEL mode")
		} else {
			log.Info("NOTE: Actions would execute SEQUENTIALLY")
		}
		log.Info("Dry run complete. No actions were executed.")
		os.Exit(0)
	}

	// If no beacon ID specified in workflow, prompt user to select
	if wf.BeaconID == "" {
		log.Info("No beacon ID specified in workflow, prompting for selection...")
		beaconID, err := selector.SelectBeacon(ctx, client)
		if err != nil {
			log.Error("Beacon selection failed: %v", err)
			os.Exit(1)
		}
		wf.BeaconID = beaconID

		// Display beacon details
		if err := selector.DisplayBeaconDetails(ctx, client, beaconID); err != nil {
			log.Warn("Could not display beacon details: %v", err)
		}
	} else {
		log.Info("Using beacon ID from workflow: %s", wf.BeaconID)
	}

	// Create workflow executor
	executor := workflow.NewExecutor(cfg.Server.Host, cfg.Server.Port, httpClient)
	executor.SetLogger(log)
	executor.SetTaskTimeout(time.Duration(cfg.Timeouts.TaskTimeout) * time.Second)

	// Track execution time
	workflowStartTime := time.Now()

	// Execute workflow (pass already authenticated credentials)
	err = executor.Execute(ctx, wf, cfg.Server.Username, cfg.Server.Password)
	workflowEndTime := time.Now()

	// Prepare output
	var outputWriter *os.File
	if *outputFile != "" {
		outputWriter, err = os.Create(*outputFile)
		if err != nil {
			log.Error("Failed to create output file: %v", err)
			os.Exit(1)
		}
		defer outputWriter.Close()
	}

	// Format and write output
	var formatter *output.Formatter
	if outputWriter != nil {
		formatter = output.NewFormatter(output.Format(*outputFormat), outputWriter)
	} else {
		formatter = output.NewFormatter(output.Format(*outputFormat), os.Stdout)
	}

	// Convert executor results to output results
	executorResults := executor.GetResults()
	outputActions := make([]output.ActionResult, len(executorResults))
	for i, r := range executorResults {
		outputActions[i] = output.ActionResult{
			Name:      r.Name,
			Type:      r.Type,
			StartTime: r.StartTime,
			EndTime:   r.EndTime,
			Duration:  r.Duration,
			Success:   r.Success,
			Output:    r.Output,
			Error:     r.Error,
		}
	}

	result := &output.Result{
		WorkflowName: wf.Name,
		BeaconID:     wf.BeaconID,
		StartTime:    workflowStartTime,
		EndTime:      workflowEndTime,
		Duration:     workflowEndTime.Sub(workflowStartTime),
		Success:      err == nil,
		Actions:      outputActions,
	}

	if err != nil {
		result.Error = err.Error()
		log.Error("Workflow execution failed: %v", err)
	} else {
		log.Info("Workflow completed successfully")
	}

	// Write formatted output
	if fmtErr := formatter.WriteResult(result); fmtErr != nil {
		log.Error("Failed to write output: %v", fmtErr)
	}

	if err != nil {
		os.Exit(1)
	}
}
