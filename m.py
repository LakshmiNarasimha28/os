import ipfshttpclient
import os
import time
import logging

# Set up basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Module 2: File Storage and Management (with IPFS)
class FileStorage:
    def __init__(self, blockchain_module, max_file_size_mb=100):
        """
        Initialize with IPFS connection, blockchain module, and max file size limit.
        
        Args:
            blockchain_module: Instance of the BlockchainIntegration class (Module 1).
            max_file_size_mb (int): Maximum file size in MB (default: 100MB).
        """
        try:
            self.ipfs = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001')
            logger.info("Connected to IPFS node")
        except Exception as e:
            raise Exception(f"Failed to connect to IPFS: {str(e)}")
        self.blockchain = blockchain_module
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024  # Convert MB to bytes

    def upload_file(self, file_content, filename, user_id):
        """Upload a file to IPFS, generate metadata, and record it on the blockchain."""
        try:
            # Validate file size
            file_size = len(file_content)
            if file_size > self.max_file_size_bytes:
                raise Exception(f"File size ({file_size} bytes) exceeds limit ({self.max_file_size_bytes} bytes)")

            # Upload to IPFS
            file_hash = self.ipfs.add_bytes(file_content)
            logger.info(f"File uploaded to IPFS with hash: {file_hash}")

            # Generate metadata
            metadata = {
                "file_id": file_hash,
                "filename": filename,
                "size": file_size,
                "type": os.path.splitext(filename)[1][1:] or "unknown",
                "hash": file_hash,
                "user_id": user_id,
                "upload_date": int(time.time())
            }

            # Record on blockchain
            success = self.blockchain.record_metadata(metadata, file_hash)
            if not success:
                raise Exception("Failed to record metadata on blockchain")

            return file_hash
        except Exception as e:
            logger.error(f"Upload error: {str(e)}")
            raise Exception(f"Failed to upload file: {str(e)}")

    def retrieve_file(self, file_hash):
        """Retrieve file content from IPFS without saving locally."""
        try:
            file_content = self.ipfs.cat(file_hash)
            logger.info(f"File retrieved from IPFS with hash: {file_hash}")
            return file_content
        except Exception as e:
            logger.error(f"Retrieval error: {str(e)}")
            raise Exception(f"Failed to retrieve file: {str(e)}")

    def download_file(self, file_hash, local_path):
        """Download a file from IPFS and save it locally."""
        try:
            file_content = self.ipfs.cat(file_hash)
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
            # Unpin the file from IPFS (removes it from local node, may still exist elsewhere)
            self.ipfs.pin_rm(file_hash)
            logger.info(f"File unpinned from IPFS with hash: {file_hash}")

            # Update blockchain (assume blockchain module has a delete method)
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

# Mock Blockchain Module (Temporary Module 1)
class MockBlockchainModule:
    def __init__(self):
        self.metadata_store = {}  # Simulate blockchain storage

    def record_metadata(self, metadata, file_hash):
        """Simulate recording metadata on the blockchain."""
        self.metadata_store[file_hash] = metadata
        logger.info(f"Recording on blockchain: {metadata}, Hash: {file_hash}")
        return True

    def delete_metadata(self, file_hash, user_id):
        """Simulate deleting metadata from the blockchain."""
        if file_hash in self.metadata_store and self.metadata_store[file_hash]["user_id"] == user_id:
            del self.metadata_store[file_hash]
            logger.info(f"Deleted metadata from blockchain for hash: {file_hash}")
            return True
        logger.warning(f"Deletion failed: hash {file_hash} not found or user {user_id} not authorized")
        return False

    def get_metadata(self, file_hash):
        """Simulate retrieving metadata from the blockchain."""
        return self.metadata_store.get(file_hash)

# Test Script
def main():
    blockchain = MockBlockchainModule()
    try:
        storage = FileStorage(blockchain, max_file_size_mb=1)  # 1MB limit for testing
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

    # Test retrieval
    try:
        retrieved_content = storage.retrieve_file(file_hash)
        print(f"Retrieved content: {retrieved_content.decode('utf-8')}")
    except Exception as e:
        print(f"Retrieval failed: {e}")
        return

    # Test download
    try:
        local_path = "downloaded_testfile.txt"
        saved_path = storage.download_file(file_hash, local_path)
        with open(saved_path, "rb") as f:
            downloaded_content = f.read()
        print(f"Downloaded content: {downloaded_content.decode('utf-8')}")
    except Exception as e:
        print(f"Download failed: {e}")
        return

    # Test metadata retrieval
    try:
        metadata = storage.get_file_metadata(file_hash)
        print(f"File metadata: {metadata}")
    except Exception as e:
        print(f"Metadata retrieval failed: {e}")
        return

    # Test deletion
    try:
        success = storage.delete_file(file_hash, "user123")
        print(f"File deletion successful: {success}")
    except Exception as e:
        print(f"Deletion failed: {e}")

if __name__ == "__main__":
    main()