# Vaidhanik

## Flask Server
| Command            | Purpose                                                                                                                   |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| make start         | Start Flask app <require `sudo`>                                                                                          |
| make server-health | Check health of all the components                                                                                        |
| make server-apps   | List all the apps in the system                                                                                           |
| make server-rules  | List all the active firewall rules                                                                                        |
| make search-app    | Lists app based on provided keyword <br> `make search-app SEARCH_TERM=firefox`                                            |
| make block-app     | Blocks an app based on `APP_NUMBER` (from @make search-apps) and `TARGET` <br> `make block-app APP_NUMBER=1 TARGET=x.com` |
| make example-block | Overview of how blocking actually works                                                                                   |
| make list-rules    | Lists all the active rules with some extra info                                                                           |
| make unblock-rule  | Unblocks a rule based on `RULE_ID`(from @make list-rules) <br> `make unblock-rule RULE_ID=83`                             |
| make cleanup-rules | Graceful shut-down of app                                                                                                 |