# dojaa/config.py

#om's API key
#SHODAN_API_KEY = "2AvEeVmSRvSMYCNI2iBLfDA5NNWAlidY"
# jon's API key
SHODAN_API_KEY = "qBA6erhzKJWy2L51g0FjgbYo4PI2vYwD"
SHODAN_QUERY = "hostname:drexel.edu"  # replace with your organization filter
CENSYS_API_TOKEN = "censys_9HAR5SGh_4YAvggoFqmQqf2czxRffiDm4"
CENSYS_API_TOKEN2 = "censys_Gt4daoEs_mkLyfvJ6jmDJEJ3VaZvpm8N3"
CENSYS_API_TOKEN3 = "censys_VBRKKgm9_N6FsiXi2qTQZ7Eap5rHqFsBq"
CENSYS_API_TOKEN4 = "censys_2gwfFZiD_F9bQmdyZuAHZmctSUyMaGsob"
CENSYS_QUERY = "services.service_name: HTTP"
ORG_DOMAIN = "drexel.edu" 
INVENTORY_FILE = "inventory.json"  # <-- adjust path as needed

DB_CONFIG = {
    "host": "localhost",
    "port": "5433",
    "database": "DOJAA",
    "user": "postgres",
    "password": "postgres",
}