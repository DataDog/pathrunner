package repl

import "fmt"

// cmdIdentity handles identity management commands
func (r *REPL) cmdIdentity(repl *REPL, args []string) error {
	// Default to list if no subcommand provided
	if len(args) == 0 {
		return r.identityManager.ListIdentities()
	}

	switch args[0] {
	case "add":
		if len(args) > 1 && args[1] == "help" {
			return r.showIdentityAddHelp()
		}
		err := r.identityManager.AddIdentity(args[1:])
		if err == nil {
			// Update prompt in case identity was added and switched to
			r.UpdatePrompt()
		}
		return err
	case "list":
		return r.identityManager.ListIdentities()
	case "show":
		return r.identityManager.ShowCurrent()
	case "switch":
		if len(args) > 1 && args[1] == "help" {
			return r.showIdentitySwitchHelp()
		}
		if len(args) < 2 {
			return NewInvalidArgumentsError("identity switch requires identity name")
		}
		err := r.identityManager.SwitchIdentity(args[1])
		if err == nil {
			r.UpdatePrompt()
		}
		return err
	case "refresh":
		return r.identityManager.RefreshCurrentIdentity()
	case "clear", "remove":
		if len(args) > 1 && args[1] == "help" {
			return r.showIdentityClearHelp()
		}
		return r.identityManager.RemoveIdentity(args[1:])
	case "help":
		return r.showIdentityHelp()
	default:
		return NewInvalidArgumentsError(fmt.Sprintf("unknown identity subcommand: %s. Use 'identity help' for available commands", args[0]))
	}
}

// cmdWhoami shows current AWS identity information
func (r *REPL) cmdWhoami(repl *REPL, args []string) error {
	if len(args) > 0 && args[0] == "help" {
		return r.showWhoamiHelp()
	}

	identity := r.identityManager.GetCurrent()
	if identity == nil {
		return NewIdentityRequiredError()
	}

	return r.identityManager.ShowCurrent()
}