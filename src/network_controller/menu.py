def display_menu():
    """Display the main menu"""
    print("\n=== Network Control System ===")
    print("1. List installed applications")
    print("2. Block application's network access")
    print("3. View/Remove blocking rules")
    print("4. View current statistics")
    print("5. Start monitoring")
    print("6. Search applications")
    print("7. View logs")
    print("8. Start proxy server")
    print("9. Stop proxy server")
    print("10. Exit")
    return input("\nSelect an option (1-10): ").strip()

def handle_block_app(controller):
    """Handle application blocking menu"""
    print("\nEnter application name (or part of name to search):")
    search = input("> ").lower()
    
    # Find matching apps
    matches = controller.search_installed_apps(search)
    
    if not matches:
        print("\nNo matching applications found")
        return
            
    # Display matches
    print("\nMatching applications:")
    for i, app in enumerate(matches, 1):
        print(f"{i}. {app}")
    
    try:
        app_idx = int(input("\nSelect application number (0 to cancel): ")) - 1
        if app_idx == -1:
            return
        if 0 <= app_idx < len(matches):
            selected_app = matches[app_idx]
            
            print("\nEnter target to block (IP or domain):")
            target = input("> ").strip()
            
            if controller.block_app_network(selected_app, target):
                print(f"\nSuccessfully blocked {selected_app} from accessing {target}")
            else:
                print("\nFailed to create blocking rule")
        else:
            print("\nInvalid selection")
    except ValueError:
        print("\nInvalid input")

def handle_view_rules(controller):
    """Handle viewing and removing blocking rules"""
    blocks = controller.get_active_blocks()
    
    if not blocks:
        print("\nNo active blocking rules")
        return
    
    print("\nCurrent blocking rules:")
    for i, block in enumerate(blocks, 1):
        print(f"{i}. {block['app']} ⟶ {block['target']}")
        print(f"   └─ Type: {block['type']}")
        print(f"   └─ IPs: {', '.join(block['ips'])}")
    
    try:
        action = input("\nEnter rule number to remove (0 to cancel): ").strip()
        if action == '0':
            return
            
        rule_idx = int(action) - 1
        if 0 <= rule_idx < len(blocks):
            block = blocks[rule_idx]
            if controller.unblock_app_network(block['id']):
                print(f"\nSuccessfully removed blocking rule")
            else:
                print("\nFailed to remove blocking rule")
        else:
            print("\nInvalid rule number")
    except ValueError:
        print("\nInvalid input")

def handle_view_logs(controller):
    """Handle viewing system logs"""
    print("\n=== Available Logs ===")
    log_files = list(controller.logs_dir.glob('*.log'))
    if not log_files:
        print("No log files found")
        return
        
    for i, log_file in enumerate(log_files, 1):
        print(f"{i}. {log_file.name}")
    
    try:
        choice = int(input("\nSelect log file to view (0 to cancel): "))
        if choice == 0:
            return
            
        if 1 <= choice <= len(log_files):
            log_file = log_files[choice - 1]
            print(f"\n=== Contents of {log_file.name} ===")
            with open(log_file, 'r') as f:
                # Show last 20 lines by default
                lines = f.readlines()
                for line in lines[-20:]:
                    print(line.strip())
                    
            input("\nPress Enter to continue...")
        else:
            print("\nInvalid selection")
    except ValueError:
        print("\nInvalid input")