package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	pb "github.com/open-edge-platform/infra-external/dm-manager/pkg/api/dm-manager"
)

var (
	endpoint   string
	timeout    time.Duration
	insec      bool
	skipVerify bool
	jwtToken   string
	jwtFile    string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "dm-cli",
		Short: "Device Management CLI for gRPC API calls",
		Long:  "A CLI tool to interact with Device Management gRPC service",
	}

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&endpoint, "endpoint", "e", "localhost:50051", "gRPC service endpoint")
	rootCmd.PersistentFlags().DurationVarP(&timeout, "timeout", "t", 30*time.Second, "Request timeout")
	rootCmd.PersistentFlags().BoolVar(&insec, "insecure", false, "Use insecure connection")
	rootCmd.PersistentFlags().BoolVar(&skipVerify, "skip-verify", false, "Skip TLS certificate verification")

	// JWT authentication flags
	rootCmd.PersistentFlags().StringVar(&jwtToken, "token", "", "JWT token for authentication")
	rootCmd.PersistentFlags().StringVar(&jwtFile, "token-file", "", "File containing JWT token")

	// Add subcommands
	rootCmd.AddCommand(
		reportAMTStatusCmd(),
		retrieveActivationDetailsCmd(),
		reportActivationResultsCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func getJWTToken() (string, error) {
	// Priority: command line flag > file > environment variable
	if jwtToken != "" {
		return jwtToken, nil
	}

	if jwtFile != "" {
		tokenBytes, err := os.ReadFile(jwtFile)
		if err != nil {
			return "", fmt.Errorf("failed to read token file %s: %w", jwtFile, err)
		}
		return strings.TrimSpace(string(tokenBytes)), nil
	}

	if envToken := os.Getenv("DM_JWT_TOKEN"); envToken != "" {
		return envToken, nil
	}

	// Token is optional - return empty string if none provided
	return "", nil
}

func createConnection() (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var opts []grpc.DialOption

	if insec {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		config := &tls.Config{
			InsecureSkipVerify: skipVerify,
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(config)))
	}

	conn, err := grpc.DialContext(ctx, endpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", endpoint, err)
	}

	return conn, nil
}

func createContextWithAuth(ctx context.Context) (context.Context, error) {
	token, err := getJWTToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get JWT token: %w", err)
	}

	if token != "" {
		// Add JWT token to gRPC metadata
		md := metadata.Pairs("authorization", "Bearer "+token)
		ctx = metadata.NewOutgoingContext(ctx, md)
	}

	return ctx, nil
}

func reportAMTStatusCmd() *cobra.Command {
	var (
		hostID  string
		status  string
		version string
	)

	cmd := &cobra.Command{
		Use:   "report-amt-status",
		Short: "Report AMT status to Device Manager",
		Long:  "Send AMT status information including host ID, status, and version",
		RunE: func(cmd *cobra.Command, args []string) error {
			return reportAMTStatus(hostID, status, version)
		},
	}

	cmd.Flags().StringVarP(&hostID, "host-id", "i", "", "Host identifier (required)")
	cmd.Flags().StringVarP(&status, "status", "s", "ENABLED", "AMT status (ENABLED or DISABLED)")
	cmd.Flags().StringVarP(&version, "version", "v", "", "AMT version")

	cmd.MarkFlagRequired("host-id")

	return cmd
}

func retrieveActivationDetailsCmd() *cobra.Command {
	var hostID string

	cmd := &cobra.Command{
		Use:   "retrieve-activation-details",
		Short: "Retrieve activation details from Device Manager",
		Long:  "Request activation details for a specific host",
		RunE: func(cmd *cobra.Command, args []string) error {
			return retrieveActivationDetails(hostID)
		},
	}

	cmd.Flags().StringVarP(&hostID, "host-id", "i", "", "Host identifier (required)")
	cmd.MarkFlagRequired("host-id")

	return cmd
}

func reportActivationResultsCmd() *cobra.Command {
	var (
		hostID  string
		status  string
		message string
	)

	cmd := &cobra.Command{
		Use:   "report-activation-results",
		Short: "Report activation results to Device Manager",
		Long:  "Send activation results including status and message",
		RunE: func(cmd *cobra.Command, args []string) error {
			return reportActivationResults(hostID, status, message)
		},
	}

	cmd.Flags().StringVarP(&hostID, "host-id", "i", "", "Host identifier (required)")
	cmd.Flags().StringVarP(&status, "status", "s", "PROVISIONED", "Activation status (PROVISIONED or FAILED)")
	cmd.Flags().StringVarP(&message, "message", "m", "", "Success or failure message")

	cmd.MarkFlagRequired("host-id")

	return cmd
}

func reportAMTStatus(hostID, statusStr, version string) error {
	conn, err := createConnection()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pb.NewDeviceManagementClient(conn)

	// Parse AMT status
	var amtStatus pb.AMTStatus
	switch statusStr {
	case "ENABLED":
		amtStatus = pb.AMTStatus_ENABLED
	case "DISABLED":
		amtStatus = pb.AMTStatus_DISABLED
	default:
		return fmt.Errorf("invalid AMT status: %s (must be ENABLED or DISABLED)", statusStr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Add JWT token to context
	ctx, err = createContextWithAuth(ctx)
	if err != nil {
		return err
	}

	req := &pb.AMTStatusRequest{
		HostId:  hostID,
		Status:  amtStatus,
		Version: version,
	}

	fmt.Printf("Reporting AMT Status:\n")
	fmt.Printf("  Host ID: %s\n", hostID)
	fmt.Printf("  Status: %s\n", statusStr)
	fmt.Printf("  Version: %s\n", version)
	fmt.Printf("  Endpoint: %s\n", endpoint)

	resp, err := client.ReportAMTStatus(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to report AMT status: %w", err)
	}

	fmt.Printf("\nResponse received successfully\n")
	fmt.Printf("Response: %+v\n", resp)

	return nil
}

func retrieveActivationDetails(hostID string) error {
	conn, err := createConnection()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pb.NewDeviceManagementClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Add JWT token to context
	ctx, err = createContextWithAuth(ctx)
	if err != nil {
		return err
	}

	req := &pb.ActivationRequest{
		HostId: hostID,
	}

	fmt.Printf("Retrieving Activation Details:\n")
	fmt.Printf("  Host ID: %s\n", hostID)
	fmt.Printf("  Endpoint: %s\n", endpoint)

	resp, err := client.RetrieveActivationDetails(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to retrieve activation details: %w", err)
	}

	fmt.Printf("\nActivation Details:\n")
	fmt.Printf("  Host ID: %s\n", resp.HostId)
	fmt.Printf("  Operation: %s\n", resp.Operation.String())
	fmt.Printf("  Profile Name: %s\n", resp.ProfileName)

	return nil
}

func reportActivationResults(hostID, statusStr, message string) error {
	conn, err := createConnection()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pb.NewDeviceManagementClient(conn)

	// Parse activation status
	var activationStatus pb.ActivationStatus
	switch statusStr {
	case "PROVISIONED":
		activationStatus = pb.ActivationStatus_PROVISIONED
	case "FAILED":
		activationStatus = pb.ActivationStatus_FAILED
	default:
		return fmt.Errorf("invalid activation status: %s (must be PROVISIONED or FAILED)", statusStr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Add JWT token to context
	ctx, err = createContextWithAuth(ctx)
	if err != nil {
		return err
	}

	req := &pb.ActivationResultRequest{
		HostId:           hostID,
		ActivationStatus: activationStatus,
		Message:          message,
	}

	fmt.Printf("Reporting Activation Results:\n")
	fmt.Printf("  Host ID: %s\n", hostID)
	fmt.Printf("  Status: %s\n", statusStr)
	fmt.Printf("  Message: %s\n", message)
	fmt.Printf("  Endpoint: %s\n", endpoint)

	resp, err := client.ReportActivationResults(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to report activation results: %w", err)
	}

	fmt.Printf("\nResponse received successfully\n")
	fmt.Printf("Response: %+v\n", resp)

	return nil
}
