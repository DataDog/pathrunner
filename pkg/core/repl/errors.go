package repl

import "fmt"

// ErrorType represents different categories of errors
type ErrorType int

const (
	ErrorCommandNotFound ErrorType = iota
	ErrorInvalidArguments
	ErrorModuleNotFound
	ErrorIdentityRequired
	ErrorSessionNotFound
	ErrorValidation
	ErrorExecution
	ErrorNetwork
	ErrorAuth
	ErrorInternal
)

// PathrunnerError is a structured error type
type PathrunnerError struct {
	Type    ErrorType
	Message string
	Cause   error
	Context map[string]interface{}
}

func (e *PathrunnerError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func (e *PathrunnerError) Unwrap() error {
	return e.Cause
}

// Error constructors
func NewCommandNotFoundError(command string) *PathrunnerError {
	return &PathrunnerError{
		Type:    ErrorCommandNotFound,
		Message: fmt.Sprintf("command '%s' not found. Type 'help' for available commands", command),
		Context: map[string]interface{}{"command": command},
	}
}

func NewInvalidArgumentsError(message string) *PathrunnerError {
	return &PathrunnerError{
		Type:    ErrorInvalidArguments,
		Message: message,
	}
}

func NewModuleNotFoundError(module string) *PathrunnerError {
	return &PathrunnerError{
		Type:    ErrorModuleNotFound,
		Message: fmt.Sprintf("module '%s' not found", module),
		Context: map[string]interface{}{"module": module},
	}
}

func NewIdentityRequiredError() *PathrunnerError {
	return &PathrunnerError{
		Type:    ErrorIdentityRequired,
		Message: "no identity configured. Use 'identity add' to add credentials",
	}
}

func NewValidationError(message string, cause error) *PathrunnerError {
	return &PathrunnerError{
		Type:    ErrorValidation,
		Message: message,
		Cause:   cause,
	}
}

func NewExecutionError(message string, cause error) *PathrunnerError {
	return &PathrunnerError{
		Type:    ErrorExecution,
		Message: message,
		Cause:   cause,
	}
}

func NewNetworkError(message string, cause error) *PathrunnerError {
	return &PathrunnerError{
		Type:    ErrorNetwork,
		Message: message,
		Cause:   cause,
	}
}

func NewAuthError(message string, cause error) *PathrunnerError {
	return &PathrunnerError{
		Type:    ErrorAuth,
		Message: message,
		Cause:   cause,
	}
}

func NewInternalError(message string, cause error) *PathrunnerError {
	return &PathrunnerError{
		Type:    ErrorInternal,
		Message: message,
		Cause:   cause,
	}
}