from .controller import NetworkController
from .menu import display_menu, handle_block_app, handle_view_rules, handle_view_logs

def main():
    """Main application loop"""
    try:
        controller = NetworkController()
        print("\nNetwork Control System Initialized")
        print(f"Found {len(controller.installed_apps)} installed applications")
        
        while True:
            choice = display_menu()
            
            if choice == "1":
                print("\nInstalled Applications:")
                for i, app in enumerate(controller.installed_apps, 1):
                    print(f"{i}. {app}")
            
            elif choice == "2":
                handle_block_app(controller)
                
            elif choice == "3":
                handle_view_rules(controller)
                
            elif choice == "4":
                controller.display_statistics()
                
            elif choice == "5":
                print("\nStarting network monitoring...")
                print("Use 'View logs' or 'View current statistics' to check status")
                controller.start_detached_monitor()            

            elif choice == "6":
                print("\nEnter search term:")
                search = input("> ").strip()
                matches = controller.search_installed_apps(search)
                
                if matches:
                    print("\nMatching applications:")
                    for app in matches:
                        print(f"- {app}")
                else:
                    print("\nNo matching applications found")
                    
            elif choice == "7":
                handle_view_logs(controller)
                
            elif choice == "8":
                if controller.start_proxy():
                    print("\nProxy server started. System proxy configured.")
                    print("You may need to restart your browsers.")
                    
            elif choice == "9":
                if controller.stop_proxy():
                    print("\nProxy server stopped. System proxy removed.")
                    print("You may need to restart your browsers.")
                    
            elif choice == "10":
                print("\nCleaning up and exiting...")
                controller.cleanup()
                break
                
            else:
                print("\nInvalid option selected")

    except KeyboardInterrupt:
        print("\n\nExiting Network Control System...")
        if 'controller' in locals():
            controller.cleanup()
    except Exception as e:
        print(f"\nError: {e}")
        print("Exiting due to error...")
        if 'controller' in locals():
            controller.cleanup()

if __name__ == "__main__":
    main()