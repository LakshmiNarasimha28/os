import ipfshttpclient
import os
import time
import logging
from Crypto.Cipher import AES  # Requires 'pycryptodome' package
import hashlib

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Module 2: File Storage and Management (with IPFS)
class FileStorage:
    def __init__(self, blockchain_module, max_file_size_mb=100, encryption_key="default_key"):
        """Initialize with IPFS, blockchain, size limit, and encryption key."""
        try:
            self.ipfs = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001')
            logger.info("Connected to IPFS node")
        except Exception as e:
            raise Exception(f"Failed to connect to IPFS: {str(e)}")
        self.blockchain = blockchain_module
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.encryption_key = encryption_key  # Default key (should be user-specific in production)

    def encrypt_file(self, content):
        """Encrypt file content using AES."""
        key = hashlib.sha256(self.encryption_key.encode()).digest()
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(content)
        return cipher.nonce + tag + ciphertext

    def decrypt_file(self, encrypted_content):
        """Decrypt file content using AES."""
        try:
            key = hashlib.sha256(self.encryption_key.encode()).digest()
            nonce, tag, ciphertext = encrypted_content[:16], encrypted_content[16:32], encrypted_content[32:]
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise Exception(f"Failed to decrypt file: {str(e)}")

    def upload_file(self, file_content, filename, user_id):
        """Upload a file to IPFS with encryption."""
        try:
            if len(file_content) > self.max_file_size_bytes:
                raise Exception(f"File size exceeds limit ({self.max_file_size_bytes} bytes)")

            # Encrypt file content
            encrypted_content = self.encrypt_file(file_content)
            file_hash = self.ipfs.add_bytes(encrypted_content)
            logger.info(f"File uploaded to IPFS with hash: {file_hash}")

            # Generate metadata
            metadata = {
                "file_id": file_hash,
                "filename": filename,
                "size": len(file_content),  # Original size before encryption
                "type": os.path.splitext(filename)[1][1:] or "unknown",
                "hash": file_hash,
                "user_id": user_id,
                "upload_date": int(time.time()),
                "version": 1  # Initial version
            }

            success = self.blockchain.record_metadata(metadata, file_hash)
            if not success:
                raise Exception("Failed to record metadata on blockchain")

            return file_hash
        except Exception as e:
            logger.error(f"Upload error: {str(e)}")
            raise Exception(f"Failed to upload file: {str(e)}")

    def retrieve_file(self, file_hash):
        """Retrieve and decrypt file content from IPFS."""
        try:
            encrypted_content = self.ipfs.cat(file_hash)
            file_content = self.decrypt_file(encrypted_content)
            logger.info(f"File retrieved from IPFS with hash: {file_hash}")
            return file_content
        except Exception as e:
            logger.error(f"Retrieval error: {str(e)}")
            raise Exception(f"Failed to retrieve file: {str(e)}")

    def download_file(self, file_hash, local_path):
        """Download and decrypt a file from IPFS to a local path."""
        try:
            encrypted_content = self.ipfs.cat(file_hash)
            file_content = self.decrypt_file(encrypted_content)
            with open(local_path, "wb") as f:
                f.write(file_content)
            logger.info(f"File downloaded from IPFS with hash: {file_hash} to {local_path}")
            return local_path
        except Exception as e:
            logger.error(f"Download error: {str(e)}")
            raise Exception(f"Failed to download file: {str(e)}")

    def delete_file(self, file_hash, user_id):
        """Unpin a file from IPFS and update the blockchain."""
        try:
            self.ipfs.pin_rm(file_hash)
            logger.info(f"File unpinned from IPFS with hash: {file_hash}")
            success = self.blockchain.delete_metadata(file_hash, user_id)
            if not success:
                raise Exception("Failed to update blockchain after deletion")
            return True
        except Exception as e:
            logger.error(f"Deletion error: {str(e)}")
            raise Exception(f"Failed to delete file: {str(e)}")

    def get_file_metadata(self, file_hash):
        """Retrieve metadata for a file from the blockchain."""
        try:
            metadata = self.blockchain.get_metadata(file_hash)
            if not metadata:
                raise Exception("Metadata not found on blockchain")
            logger.info(f"Retrieved metadata for hash: {file_hash} - {metadata}")
            return metadata
        except Exception as e:
            logger.error(f"Metadata retrieval error: {str(e)}")
            raise Exception(f"Failed to retrieve metadata: {str(e)}")

    def verify_file_integrity(self, file_hash):
        """Verify file integrity by comparing stored and computed hashes."""
        try:
            stored_metadata = self.blockchain.get_metadata(file_hash)
            if not stored_metadata:
                raise Exception("Metadata not found on blockchain")

            encrypted_content = self.ipfs.cat(file_hash)
            computed_hash = self.ipfs.add_bytes(encrypted_content)

            if computed_hash != stored_metadata['hash']:
                raise Exception("File integrity compromised! Hash mismatch")

            logger.info(f"File integrity verified for hash: {file_hash}")
            return True
        except Exception as e:
            logger.error(f"Integrity verification failed: {str(e)}")
            return False

    def search_files(self, user_id=None, file_type=None, filename=None):
        """Search files based on user_id, file_type, or filename."""
        try:
            results = []
            for file_hash, metadata in self.blockchain.metadata_store.items():
                if user_id and metadata['user_id'] != user_id:
                    continue
                if file_type and metadata['type'] != file_type:
                    continue
                if filename and filename.lower() not in metadata['filename'].lower():
                    continue
                results.append(metadata)
            logger.info(f"Search returned {len(results)} results")
            return results
        except Exception as e:
            logger.error(f"Search error: {str(e)}")
            return []

    def upload_new_version(self, original_file_hash, new_content, user_id):
        """Upload a new version of an existing file."""
        try:
            new_file_hash = self.ipfs.add_bytes(self.encrypt_file(new_content))
            original_metadata = self.blockchain.get_metadata(original_file_hash)

            if not original_metadata or original_metadata["user_id"] != user_id:
                raise Exception("Original file not found or unauthorized")

            version_number = original_metadata.get("version", 1) + 1
            new_metadata = {
                "file_id": new_file_hash,
                "filename": original_metadata["filename"],
                "size": len(new_content),
                "type": original_metadata["type"],
                "hash": new_file_hash,
                "user_id": user_id,
                "upload_date": int(time.time()),
                "version": version_number
            }

            success = self.blockchain.record_metadata(new_metadata, new_file_hash)
            if not success:
                raise Exception("Failed to record new version on blockchain")
            logger.info(f"New version uploaded: {new_file_hash}, version: {version_number}")
            return new_file_hash
        except Exception as e:
            logger.error(f"Version upload error: {str(e)}")
            return None

# Mock Blockchain Module (Temporary Module 1)
class MockBlockchainModule:
    def __init__(self):
        self.metadata_store = {}

    def record_metadata(self, metadata, file_hash):
        self.metadata_store[file_hash] = metadata
        logger.info(f"Recording on blockchain: {metadata}, Hash: {file_hash}")
        return True

    def delete_metadata(self, file_hash, user_id):
        if file_hash in self.metadata_store and self.metadata_store[file_hash]["user_id"] == user_id:
            del self.metadata_store[file_hash]
            logger.info(f"Deleted metadata from blockchain for hash: {file_hash}")
            return True
        logger.warning(f"Deletion failed: hash {file_hash} not found or user {user_id} not authorized")
        return False

    def get_metadata(self, file_hash):
        return self.metadata_store.get(file_hash)

# Test Script
def main():
    blockchain = MockBlockchainModule()
    try:
        storage = FileStorage(blockchain, max_file_size_mb=1, encryption_key="my_secret_key")
    except Exception as e:
        print(f"Failed to initialize FileStorage: {e}")
        return

    # Test upload
    sample_content = b"Testing Module 2 with IPFS and new features!"
    try:
        file_hash = storage.upload_file(sample_content, "testfile.txt", "user123")
        print(f"Uploaded file hash: {file_hash}")
    except Exception as e:
        print(f"Upload failed: {e}")
        return

    # Test integrity verification
    try:
        is_valid = storage.verify_file_integrity(file_hash)
        print(f"File integrity valid: {is_valid}")
    except Exception as e:
        print(f"Integrity check failed: {e}")

    # Test retrieval
    try:
        retrieved_content = storage.retrieve_file(file_hash)
        print(f"Retrieved content: {retrieved_content.decode('utf-8')}")
    except Exception as e:
        print(f"Retrieval failed: {e}")

    # Test download
    try:
        local_path = "downloaded_testfile.txt"
        saved_path = storage.download_file(file_hash, local_path)
        with open(saved_path, "rb") as f:
            downloaded_content = f.read()
        print(f"Downloaded content: {downloaded_content.decode('utf-8')}")
    except Exception as e:
        print(f"Download failed: {e}")

    # Test metadata retrieval
    try:
        metadata = storage.get_file_metadata(file_hash)
        print(f"File metadata: {metadata}")
    except Exception as e:
        print(f"Metadata retrieval failed: {e}")

    # Test search
    try:
        results = storage.search_files(user_id="user123", filename="testfile")
        print(f"Search results: {results}")
    except Exception as e:
        print(f"Search failed: {e}")

    # Test versioning
    try:
        new_content = b"Updated content for version 2!"
        new_hash = storage.upload_new_version(file_hash, new_content, "user123")
        print(f"New version hash: {new_hash}")
        new_metadata = storage.get_file_metadata(new_hash)
        print(f"New version metadata: {new_metadata}")
    except Exception as e:
        print(f"Versioning failed: {e}")

    # Test deletion
    try:
        success = storage.delete_file(file_hash, "user123")
        print(f"File deletion successful: {success}")
    except Exception as e:
        print(f"Deletion failed: {e}")

if __name__ == "__main__":
    main()