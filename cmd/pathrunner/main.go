package main

import (
	"os"
	"pathrunner/pkg/cli"

	// Import payloads to register them
	_ "pathrunner/pkg/payloads/ec2"
	_ "pathrunner/pkg/payloads/glue"
	_ "pathrunner/pkg/payloads/lambda"

	// Import modules to register them
	_ "pathrunner/pkg/exploits/ec2_passrole"
	_ "pathrunner/pkg/exploits/glue_passrole_job"
	_ "pathrunner/pkg/exploits/iam_addusertogroup"
	_ "pathrunner/pkg/exploits/iam_attachgrouppolicy"
	_ "pathrunner/pkg/exploits/iam_attachrolepolicy"
	_ "pathrunner/pkg/exploits/iam_attachrolepolicy_assumerole"
	_ "pathrunner/pkg/exploits/iam_attachrolepolicy_updateassumerolepolicy"
	_ "pathrunner/pkg/exploits/iam_attachuserpolicy"
	_ "pathrunner/pkg/exploits/iam_attachuserpolicy_createaccesskey"
	_ "pathrunner/pkg/exploits/iam_create_policy_version"
	_ "pathrunner/pkg/exploits/iam_createaccesskey"
	_ "pathrunner/pkg/exploits/iam_createloginprofile"
	_ "pathrunner/pkg/exploits/iam_createpolicyversion_assumerole"
	_ "pathrunner/pkg/exploits/iam_createpolicyversion_updateassumerolepolicy"
	_ "pathrunner/pkg/exploits/iam_deleteaccesskey_createaccesskey"
	_ "pathrunner/pkg/exploits/iam_putgrouppolicy"
	_ "pathrunner/pkg/exploits/iam_putrolepolicy"
	_ "pathrunner/pkg/exploits/iam_putrolepolicy_assumerole"
	_ "pathrunner/pkg/exploits/iam_putrolepolicy_updateassumerolepolicy"
	_ "pathrunner/pkg/exploits/iam_putuserpolicy"
	_ "pathrunner/pkg/exploits/iam_putuserpolicy_createaccesskey"
	_ "pathrunner/pkg/exploits/iam_updateassumerolepolicy"
	_ "pathrunner/pkg/exploits/iam_updateloginprofile"
	_ "pathrunner/pkg/exploits/lambda_createfunction_addpermission"
	_ "pathrunner/pkg/exploits/lambda_passrole"
	_ "pathrunner/pkg/exploits/lambda_passrole_esm"
	_ "pathrunner/pkg/exploits/lambda_updatecode"
	_ "pathrunner/pkg/exploits/lambda_updatecode_addpermission"
	_ "pathrunner/pkg/exploits/lambda_updatecode_invoke"
	_ "pathrunner/pkg/exploits/sts_assume_role"
)

func main() {
	cliApp := cli.NewCLI()
	rootCmd := cliApp.CreateRootCommand()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}