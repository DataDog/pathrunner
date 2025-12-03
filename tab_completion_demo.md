# Tab Completion Demo

Pathrunner now supports comprehensive tab completion for all commands!

## ✅ New Tab Completion Features:

### **Command Completion:**
- Type `he` + TAB → completes to `help`
- Type `ident` + TAB → completes to `identity`
- Type `ex` + TAB → shows `exit` and `exploit` options

### **Subcommand Completion:**
- `help` + TAB → shows all commands you can get help for
- `identity` + TAB → shows `list`, `current`, `add`, `switch`, `help`
- `show` + TAB → shows `options`, `modules`, `payloads`, `payload`, `help`

### **Module Completion:**
- `use` + TAB → shows all available modules
- `use exp` + TAB → completes to `exploit/lambda_passrole`

### **Dynamic Payload Completion:**
```bash
pathrunner> use exploit/lambda_passrole
pathrunner> set PAYLOAD + TAB
# Shows: exfil/output, exfil/https, persist/backdoor_role, persist/backdoor_user
```

### **Option Completion:**
```bash
pathrunner> set + TAB
# Shows: ROLE_ARN, PAYLOAD, FUNCTION_NAME, RUNTIME, TIMEOUT, MEMORY_SIZE, CLEANUP

pathrunner> set PAYLOAD exfil/https
pathrunner> set + TAB
# Now also shows: HTTPS_URL, USER_AGENT, TIMEOUT, INCLUDE_ENV (payload-specific options)
```

### **Identity Completion:**
```bash
pathrunner> identity add --profile myprofile
pathrunner> identity switch + TAB
# Shows: myprofile (and any other configured identities)
```

### **Unset Completion:**
```bash
pathrunner> unset + TAB
# Shows all currently set options that can be unset
```

## 🎯 Interactive Features:
- **Context-Aware**: Completions change based on current module and payload selection
- **Dynamic Updates**: Adding identities immediately updates completion options
- **Multi-Level**: Supports nested completions (e.g., `identity add --` + TAB shows `--profile`, `--keys`, `--from-output`)

This makes the tool much more discoverable and user-friendly for penetration testers!