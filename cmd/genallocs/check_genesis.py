import json

def sum_balances(filename):
    # Open the file and load the JSON data
    with open(filename, 'r') as file:
        data = json.load(file)

    # Initialize a variable to store the total sum
    total_balance = 0

    # Iterate over each entry and sum up the balances
    for entry in data:
        for balance in entry.get('balanceSchedule', {}).values():
            total_balance += balance
            # Print the address when balance is zero
            if balance == 0:
                print(entry.get('address'))

    return total_balance

# Example usage
filename = "genesis_alloc.json"  # Replace with your actual file name
total = sum_balances(filename)
print(f"Total Balance: {total}")
