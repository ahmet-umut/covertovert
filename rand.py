import random
import json


def generate_json_file(filename="./code/config.json"):
    # Step 1. Set parameters
    biti, bito = 2, 4
    set_i = list(range(2**biti))        # [0, 1, 2, 3] for biti=2
    set_o = list(range(2**bito))        # [0, 1, 2, 3] for bito=2

    # Shuffle set_o to create a random mapping
    random.shuffle(set_o)

    # Helper function to convert an integer to n-bit binary string
    def fn(x, n): return bin(x)[2:].zfill(n)

    # Step 2. Create the random mapping dict
    # Initialize dict with keys '00', '01', '10', '11'
    dict_mapping = {fn(k, biti): set() for k in range(2**biti)}

    # For each i in set_i, map it to the (shuffled) set_o[i]
    for i in set_i:
        dict_mapping[fn(i, biti)].add(fn(set_o[i], bito))

    # set_o[4:] is empty for 2-bit input/output, but we'll keep the code generic
    setm = set(set_o[2**biti:])  # might be empty for these parameters
    for i in setm:
        dict_mapping[fn(random.choice(set_i), biti)].add(fn(i, bito))

    # Convert sets to strings for JSON (or to lists if you prefer)
    # We'll store the entire dictionary mapping as a string (like the sample).
    dict_mapping_str = str(dict_mapping)

    # Step 3. Create the JSON structure
    json_data = {
        "covert_channel_code": "Replace it with the [Code] of chosen covert channel type seen in ODTUClass.",
        "send": {
            "parameters": {
                "log_file_name": "sender.log",
                "biti": biti,
                "bito": bito,
                "encoding": dict_mapping_str
            }
        },
        "receive": {
            "parameters": {
                "log_file_name": "receiver.log",
                "biti": biti,
                "bito": bito,
                "encoding": dict_mapping_str
            }
        }
    }

    # Step 4. Write the JSON to file
    with open(filename, "w") as f:
        json.dump(json_data, f, indent=2)

    print(f"JSON file '{filename}' has been generated!")


if __name__ == "__main__":
    generate_json_file()