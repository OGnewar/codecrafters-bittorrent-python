import json
import sys
import hashlib
import bencodepy

bc = bencodepy.Bencode(encoding="utf-8")

def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        length = int(bencoded_value[:first_colon_index])
        start_index = first_colon_index + 1
        return bencoded_value[start_index:start_index+length]
    elif bencoded_value.startswith(b"i"):
        return int(bencoded_value[1:-1])
    elif bencoded_value.startswith(b"l"):  # list
        return bc.decode(bencoded_value)
    elif bencoded_value.startswith(b"d"):  # dictionary
        return bc.decode(bencoded_value)
    else:
        raise NotImplementedError("Unsupported bencode type")

def bytes_to_str(data):
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    elif isinstance(data, int):
        return data
    elif isinstance(data, list):
        return [bytes_to_str(item) for item in data]
    elif isinstance(data, dict):
        return {bytes_to_str(k): bytes_to_str(v) for k, v in data.items()}
    else:
        raise TypeError(f"Type not serializable: {type(data)}")

def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        torrent_file_path = sys.argv[2]
        with open(torrent_file_path, "rb") as file:
            content = file.read()
        decoded_content = bencodepy.decode(content)
        info = bytes_to_str(decoded_content)
        info_hash = hashlib.sha1(bencodepy.encode(decoded_content[b"info"])).hexdigest()
        
        print(f'Tracker URL: {info["announce"]}')
        print(f'Length: {info["info"]["length"]}')
        print(f"Info Hash: {info_hash}")
        
        piece_length = decoded_content[b"info"][b"piece length"]
        pieces = decoded_content[b"info"][b"pieces"]
        piece_hashes = [pieces[i:i+20].hex() for i in range(0, len(pieces), 20)]
        
        print(f"Piece Length: {piece_length}")
        print("Piece Hashes:")
        for piece_hash in piece_hashes:
            print(piece_hash)
    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()
