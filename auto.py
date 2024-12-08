from pymongo import MongoClient

# MongoDB connection details
mongo_instances = [
    {"host": "localhost", "port": 27018, "username": "mongorulesuser", "password": "rulespass"},
    {"host": "localhost", "port": 27019, "username": "mongoattemptsuser", "password": "attemptspass"},
    {"host": "localhost", "port": 27020, "username": "mongomonitor", "password": "monitorpass"},
    {"host": "localhost", "port": 27021, "username": "mongoaiuser", "password": "aipass"},
]

def clear_databases(instance):
    """Connects to a MongoDB instance and drops all databases except system ones."""
    client = MongoClient(
        host=instance["host"],
        port=instance["port"],
        username=instance["username"],
        password=instance["password"],
    )
    # List databases and drop them
    for db_name in client.list_database_names():
        if db_name not in ("admin", "local", "config"):
            print(f"Dropping database '{db_name}' from {instance['host']}:{instance['port']}")
            try:
                client.drop_database(db_name)
            except Exception as e:
                print(f"Failed to drop database '{db_name}': {e}")

# Clear databases in all instances
for instance in mongo_instances:
    clear_databases(instance)
