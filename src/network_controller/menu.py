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
    print("11. View Connection Patterns")
    print("12. Debug: Check Monitor Data")
    print("13. Implement AI Recommendation")
    return input("\nSelect an option (1-13): ").strip()

def handle_implement_recommendation(controller):
    """Handle implementing AI recommendation"""
    try:
        # First show current recommendations
        recommendations = controller.interceptor.db.get_inactive_ai_recommendations()
        
        if not recommendations:
            print("\nNo Inactive AI recommendations found")
            return
            
        print("\nAvailable AI Recommendations:")
        for rec in recommendations:
            # Get implementation status markers
            is_implemented = '✓' if rec.get('implemented', False) else ' '
            impl_status = rec.get('implementation_status', 'pending')
            impl_time = rec.get('implementation_time', 'Not implemented')
            
            # Print recommendation info
            print(f"\n[{is_implemented}] ID {rec['id']}: {rec['app_name']} → {rec['dest_ip']}")
            print(f"   └─ Confidence: {rec['confidence'] * 100:.1f}%")
            print(f"   └─ Reason: {rec['reason']}")
            print(f"   └─ Status: {impl_status}")
            print(f"   └─ Implementation Time: {impl_time}")
            print(f"   └─ Last Updated: {rec['updated_at']}")
            
        # Get recommendation to implement
        rec_id = input("\nEnter recommendation ID to implement (0 to cancel): ").strip()
        if rec_id == '0':
            return
            
        try:
            rec_id = int(rec_id)
        except ValueError:
            print("\nInvalid ID format")
            return
            
        # Check if already implemented
        selected_rec = next((r for r in recommendations if r['id'] == rec_id), None)
        if selected_rec and selected_rec.get('implemented', False):
            print(f"\nRecommendation {rec_id} is already implemented")
            return
        
        # Implement recommendation
        if controller.implement_ai_recommendation(rec_id):
            print(f"\n✓ Successfully implemented recommendation {rec_id}")
        else:
            print(f"\n✗ Failed to implement recommendation {rec_id}")
            
    except Exception as e:
        print(f"Error handling recommendation implementation: {e}")

def check_monitor_data(controller):
    """Check if monitor is storing data"""
    try:
        # Get monitor database connection
        monitor_db = controller.interceptor.db.db
        connections = list(monitor_db.connections.find().limit(5))
        
        print(f"\nFound {len(connections)} monitored connections")
        if connections:
            print("\nRecent monitored connections:")
            for conn in connections:
                print(f"- {conn['app_name']} → {conn['remote_addr']}:{conn['remote_port']}")
        else:
            print("\nNo monitored connections found")
            print("Please make sure:")
            print("1. Monitoring is started (Option 5)")
            print("2. There is network activity")
            
    except Exception as e:
        print(f"Error checking monitor data: {e}")

def handle_analyze_connections(controller):
    """Analyze historical connections and show recommendations"""
    try:
        print("\nAnalyzing connection history...")
        recommendations = controller.interceptor.db.analyze_historical_connections(n_records=100)
        
        if not recommendations:
            print("\nNo blocking recommendations found")
            return
            
        print(f"\nFound {len(recommendations)} potential blocks:")
        
        for rec in recommendations:
            confidence = rec['confidence'] * 100
            print(f"\n[ID: {rec['id']}] {rec['app_name']} → {rec['dest_ip']}")
            print(f"   └─ Confidence: {confidence:.1f}%")
            print(f"   └─ Reason: {rec['reason']}")
            print(f"   └─ Connections: {rec['connection_count']}")
            
            if 'analysis' in rec:
                metrics = rec['analysis'].get('metrics', {})
                if metrics:
                    print(f"   └─ Details:")
                    print(f"      └─ Ports: {metrics.get('unique_ports', 'N/A')}")
                    print(f"      └─ Frequency: {metrics.get('frequency', 0):.2f} conn/sec")
                    print(f"      └─ Protocols: {', '.join(metrics.get('protocols', []))}")
                    
    except Exception as e:
        print(f"Error during analysis: {e}")

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