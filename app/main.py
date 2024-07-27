import json
import sys
import hashlib
import bencodepy
import requests
import urllib.parse

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
    elif command == "peers":
        torrent_file_path = sys.argv[2]
        with open(torrent_file_path, "rb") as file:
            content = file.read()
        decoded_content = bencodepy.decode(content)
        info = decoded_content[b"info"]
        info_hash = hashlib.sha1(bencodepy.encode(info)).digest()
        tracker_url = decoded_content[b"announce"].decode()
        total_length = info[b"length"]
        
        peer_id = "00112233445566778899"
        port = 6881
        uploaded = 0
        downloaded = 0
        left = total_length
        compact = 1
        
        query_params = {
            "info_hash": urllib.parse.quote(info_hash),
            "peer_id": peer_id,
            "port": port,
            "uploaded": uploaded,
            "downloaded": downloaded,
            "left": left,
            "compact": compact
        }
        
        response = requests.get(tracker_url, params=query_params)
        response_data = bencodepy.decode(response.content)
        peers = response_data[b"peers"]
        
        peer_list = []
        for i in range(0, len(peers), 6):
            ip = ".".join(map(str, peers[i:i+4]))
            port = int.from_bytes(peers[i+4:i+6], byteorder='big')
            peer_list.append(f"{ip}:{port}")
        
        for peer in peer_list:
            print(peer)
    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()
