import sys
import socket
import hashlib
import struct

def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        length = int(bencoded_value[:first_colon_index])
        return (
            bencoded_value[first_colon_index + 1 : first_colon_index + 1 + length],
            bencoded_value[first_colon_index + 1 + length :],
        )
    elif chr(bencoded_value[0]) == "i":
        end_index = bencoded_value.find(b"e")
        if end_index == -1:
            raise ValueError("Invalid encoded value")
        return int(bencoded_value[1:end_index]), bencoded_value[end_index + 1 :]
    elif chr(bencoded_value[0]) == "l":
        list_values = []
        remaining = bencoded_value[1:]
        while remaining[0] != ord("e"):
            decoded, remaining = decode_bencode(remaining)
            list_values.append(decoded)
        return list_values, remaining[1:]
    elif chr(bencoded_value[0]) == "d":
        dict_values = {}
        remaining = bencoded_value[1:]
        while remaining[0] != ord("e"):
            key, remaining = decode_bencode(remaining)
            if isinstance(key, bytes):
                key = key.decode()
            value, remaining = decode_bencode(remaining)
            dict_values[key] = value
        return dict_values, remaining[1:]
    else:
        raise NotImplementedError(
            "Only strings, integers, lists, and dictionaries are supported at the moment"
        )

def bencode(data):
    if isinstance(data, str):
        return f"{len(data)}:{data}".encode()
    elif isinstance(data, bytes):
        return f"{len(data)}:".encode() + data
    elif isinstance(data, int):
        return f"i{data}e".encode()
    elif isinstance(data, list):
        return b"l" + b"".join(bencode(item) for item in data) + b"e"
    elif isinstance(data, dict):
        encoded_dict = b"".join(
            bencode(key) + bencode(value) for key, value in sorted(data.items())
        )
        return b"d" + encoded_dict + b"e"
    else:
        raise TypeError(f"Type not serializable: {type(data)}")

def main():
    command = sys.argv[1]
    if command == "handshake":
        torrent_file = sys.argv[2]
        peer_address = sys.argv[3]
        peer_ip, peer_port = peer_address.split(":")
        peer_port = int(peer_port)

        # Read and parse the torrent file
        with open(torrent_file, "rb") as f:
            bencoded_value = f.read()
        torrent_info, _ = decode_bencode(bencoded_value)
        info_dict = torrent_info.get("info", {})
        bencoded_info = bencode(info_dict)
        info_hash = hashlib.sha1(bencoded_info).digest()

        # Create the handshake message
        pstr = b"BitTorrent protocol"
        pstrlen = struct.pack("!B", len(pstr))
        reserved = b'\x00' * 8
        peer_id = b'00112233445566778899'
        handshake_message = pstrlen + pstr + reserved + info_hash + peer_id

        # Establish TCP connection with the peer
        with socket.create_connection((peer_ip, peer_port)) as s:
            s.sendall(handshake_message)
            response = s.recv(68)
            if len(response) != 68:
                raise ValueError("Invalid handshake response length")
            
            # Extract the peer ID from the handshake response
            received_peer_id = response[48:68]
            print(f"Peer ID: {received_peer_id.hex()}")
    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()
