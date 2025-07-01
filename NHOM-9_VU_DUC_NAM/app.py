import asyncio
import websockets
import json
import base64
import hashlib
import time
from datetime import datetime
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import logging
import os 

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

#  Cấu hình file log
LOG_FILE = "encryption_log.json"

class VoiceChatServer:
    def __init__(self):
        self.clients = {}  # {websocket: client_info}
        self.rooms = {}    # {room_id: [websockets]}
        # [THÊM VÀO] Khởi tạo file log nếu chưa tồn tại
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'w') as f:
                json.dump([], f)

    # [THÊM VÀO] Hàm ghi log vào file JSON
    def log_event(self, event_data):
        """Ghi một sự kiện vào file log JSON."""
        try:
            with open(LOG_FILE, 'r+') as f:
                logs = json.load(f)
                logs.append(event_data)
                f.seek(0)
                json.dump(logs, f, indent=4)
        except Exception as e:
            logger.error(f"Could not write to log file: {e}")
            
    async def register_client(self, websocket, path):
        """Đăng ký client mới"""
        try:
            self.clients[websocket] = {
                'id': id(websocket),
                'room': None,
                'public_key': None,
                'private_key': None,
                'username': None,
                'session_keys': {}  # {peer_id: des_key}
            }
            logger.info(f"Client {id(websocket)} connected")
            await websocket.send(json.dumps({
                'type': 'connection_established',
                'client_id': id(websocket)
            }))
            
            async for message in websocket:
                await self.handle_message(websocket, message)
                
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Client {id(websocket)} disconnected")
        finally:
            await self.unregister_client(websocket)
    
    async def unregister_client(self, websocket):
        """Hủy đăng ký client"""
        if websocket in self.clients:
            client_info = self.clients[websocket]
            if client_info['room']:
                await self.leave_room(websocket, client_info['room'])
            del self.clients[websocket]
    
    async def handle_message(self, websocket, message):
        """Xử lý tin nhắn từ client"""
        try:
            data = json.loads(message)
            message_type = data.get('type')
            
            if message_type == 'generate_keys':
                await self.generate_rsa_keys(websocket)
            elif message_type == 'join_room':
                await self.join_room(websocket, data.get('room_id'), data.get('username'))
            elif message_type == 'leave_room':
                await self.leave_room(websocket, data.get('room_id'))
            elif message_type == 'handshake_request':
                await self.handle_handshake_request(websocket, data)
            elif message_type == 'handshake_response':
                await self.handle_handshake_response(websocket, data)
            elif message_type == 'key_exchange':
                await self.handle_key_exchange(websocket, data)
            elif message_type == 'voice_message':
                await self.handle_voice_message(websocket, data)
            elif message_type == 'ack':
                await self.handle_ack(websocket, data)
                
        except Exception as e:
            logger.error(f"Error handling message: {e}")
            await websocket.send(json.dumps({
                'type': 'error',
                'message': str(e)
            }))
    
    async def generate_rsa_keys(self, websocket):
        """Tạo cặp khóa RSA cho client"""
        try:
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()
            
            self.clients[websocket]['private_key'] = key
            self.clients[websocket]['public_key'] = key.publickey()
            
            await websocket.send(json.dumps({
                'type': 'keys_generated',
                'public_key': public_key.decode(),
                'private_key': private_key.decode()
            }))
            
        except Exception as e:
            logger.error(f"Error generating RSA keys: {e}")
    
    async def join_room(self, websocket, room_id, username):
        """Client tham gia phòng chat"""
        # ... (giữ nguyên không đổi)
        try:
            if room_id not in self.rooms:
                self.rooms[room_id] = []
            
            self.rooms[room_id].append(websocket)
            self.clients[websocket]['room'] = room_id
            self.clients[websocket]['username'] = username
            
            room_clients = []
            for client_ws in self.rooms[room_id]:
                if client_ws != websocket and client_ws in self.clients:
                    client_info = self.clients[client_ws]
                    room_clients.append({
                        'id': client_info['id'],
                        'username': client_info['username'],
                        'public_key': client_info['public_key'].export_key().decode() if client_info['public_key'] else None
                    })
                    
                    await client_ws.send(json.dumps({
                        'type': 'user_joined',
                        'user': {
                            'id': self.clients[websocket]['id'],
                            'username': username,
                            'public_key': self.clients[websocket]['public_key'].export_key().decode() if self.clients[websocket]['public_key'] else None
                        }
                    }))
            
            await websocket.send(json.dumps({
                'type': 'room_joined',
                'room_id': room_id,
                'clients': room_clients
            }))
            
        except Exception as e:
            logger.error(f"Error joining room: {e}")
    
    async def leave_room(self, websocket, room_id):
        """Client rời khỏi phòng chat"""
        # ... (giữ nguyên không đổi)
        try:
            if room_id in self.rooms and websocket in self.rooms[room_id]:
                self.rooms[room_id].remove(websocket)
                
                for client_ws in self.rooms[room_id]:
                    await client_ws.send(json.dumps({
                        'type': 'user_left',
                        'user_id': self.clients[websocket]['id']
                    }))
                
                if not self.rooms[room_id]:
                    del self.rooms[room_id]
                    
                self.clients[websocket]['room'] = None
                
        except Exception as e:
            logger.error(f"Error leaving room: {e}")
    
    async def handle_handshake_request(self, websocket, data):
        """Xử lý yêu cầu handshake"""
        # ... (giữ nguyên không đổi)
        try:
            target_id = data.get('target_id')
            current_client_ids = [info['id'] for info in self.clients.values()]
            logger.info(f"Yêu cầu từ client {self.clients[websocket]['id']} tới target_id: {target_id}")
            logger.info(f"Các client IDs hiện có trên server: {current_client_ids}")
            target_ws = self.find_client_by_id(target_id)
            
            if target_ws:
                await target_ws.send(json.dumps({
                    'type': 'handshake_request',
                    'from_id': self.clients[websocket]['id'],
                    'from_username': self.clients[websocket]['username'],
                    'message': 'Hello Mr.B, I\'m A!'
                }))
            else:
                await websocket.send(json.dumps({
                    'type': 'error',
                    'message': 'Target client not found'
                }))
                
        except Exception as e:
            logger.error(f"Error handling handshake request: {e}")
    
    async def handle_handshake_response(self, websocket, data):
        """Xử lý phản hồi handshake"""
        # ... (giữ nguyên không đổi)
        try:
            target_id = data.get('target_id')
            target_ws = self.find_client_by_id(target_id)
            
            if target_ws:
                await target_ws.send(json.dumps({
                    'type': 'handshake_response',
                    'from_id': self.clients[websocket]['id'],
                    'from_username': self.clients[websocket]['username'],

                    'message': 'Hi A, I\'m Ready!',
                    'public_key': self.clients[websocket]['public_key'].export_key().decode()
                }))
                
                await websocket.send(json.dumps({
                    'type': 'public_key_received',
                    'from_id': target_id,
                    'public_key': self.clients[target_ws]['public_key'].export_key().decode()
                }))
            else:
                await websocket.send(json.dumps({
                    'type': 'error',
                    'message': 'Target client not found'
                }))
                
        except Exception as e:
            logger.error(f"Error handling handshake response: {e}")
    
    async def handle_key_exchange(self, websocket, data):
        """Xử lý trao đổi khóa DES (Bước 2)"""
        try:
            target_id = data.get('target_id')
            target_ws = self.find_client_by_id(target_id)
            
            if not target_ws:
                # ... (giữ nguyên)
                return
            
            des_key = get_random_bytes(8)
            sender_id = self.clients[websocket]['id']
            self.clients[websocket]['session_keys'][target_id] = des_key
            self.clients[target_ws]['session_keys'][sender_id] = des_key
            
            timestamp = int(time.time())
            metadata = f"{sender_id}:{target_id}:{timestamp}"
            
            private_key = self.clients[websocket]['private_key']
            h = SHA256.new(metadata.encode())
            signature = pkcs1_15.new(private_key).sign(h)
            
            target_public_key = self.clients[target_ws]['public_key']
            cipher_rsa = PKCS1_OAEP.new(target_public_key, hashAlgo=SHA256)
            encrypted_des_key = cipher_rsa.encrypt(des_key)
            
            # [THÊM VÀO] Tạo payload và ghi log
            b64_signature = base64.b64encode(signature).decode()
            b64_encrypted_key = base64.b64encode(encrypted_des_key).decode()

            log_payload = {
                "metadata": metadata,
                "signed_info": b64_signature,
                "encrypted_des_key": b64_encrypted_key
            }
            self.log_event({
                "timestamp": datetime.now().isoformat(),
                "event_type": "Key Exchange Sent",
                "sender_id": sender_id,
                "receiver_id": target_id,
                "payload": log_payload
            })

            await target_ws.send(json.dumps({
                'type': 'key_exchange',
                'from_id': sender_id,
                'signed_info': b64_signature,
                'encrypted_des_key': b64_encrypted_key,
                'metadata': metadata,
                'timestamp': timestamp
            }))
            
            await websocket.send(json.dumps({
                'type': 'key_exchange_sent',
                'target_id': target_id,
                'session_key_established': True
            }))
            
        except Exception as e:
            logger.error(f"Error handling key exchange: {e}")
    
    async def handle_voice_message(self, websocket, data):
        """Xử lý tin nhắn âm thanh đã mã hóa (Bước 3)"""
        try:
            target_id = data.get('target_id')
            target_ws = self.find_client_by_id(target_id)
            sender_id = self.clients[websocket]['id']
            
            if not target_ws:
                # ... (giữ nguyên)
                return
            
            # [THÊM VÀO] Ghi log gói tin thoại được chuyển tiếp
            log_payload = {
                "cipher": data.get('cipher'),
                "hash": data.get('hash'),
                "sig": data.get('sig')
            }
            self.log_event({
                "timestamp": datetime.now().isoformat(),
                "event_type": "Voice Message Forwarded",
                "sender_id": sender_id,
                "receiver_id": target_id,
                "payload": log_payload
            })

            await target_ws.send(json.dumps({
                'type': 'voice_message',
                'from_id': sender_id,
                'from_username': self.clients[websocket]['username'],
                'cipher': data.get('cipher'),
                'hash': data.get('hash'),
                'sig': data.get('sig'),
                'timestamp': data.get('timestamp', int(time.time()))
            }))
            
        except Exception as e:
            logger.error(f"Error handling voice message: {e}")
    
    async def handle_ack(self, websocket, data):
        """Xử lý ACK/NACK"""
        # ... (giữ nguyên không đổi)
        try:
            target_id = data.get('target_id')
            target_ws = self.find_client_by_id(target_id)
            
            if target_ws:
                await target_ws.send(json.dumps({
                    'type': 'ack_received',
                    'from_id': self.clients[websocket]['id'],
                    'status': data.get('status'),
                    'message': data.get('message', '')
                }))
                
        except Exception as e:
            logger.error(f"Error handling ACK: {e}")
    
    def find_client_by_id(self, client_id):
        """Tìm websocket theo client ID"""
        for ws, info in self.clients.items():
            if info['id'] == client_id:
                return ws
        return None

# Khởi tạo server
server = VoiceChatServer()

if __name__ == "__main__":
    print(f"Starting Voice Chat Server on ws://localhost:8765")
    print(f"Logging encryption events to {LOG_FILE}") 
    start_server = websockets.serve(server.register_client, "localhost", 8765)
    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_forever()