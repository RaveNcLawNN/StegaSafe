class MockKeyProvider:
    def list_keys(self, kind=None, role=None):
        return [
            {
                "id": "demo-aes-key",
                "name": "Demo AES-256 Key",
                "kind": "symmetric",
                "algorithm": "AES",
                "bits": 256,
            }
        ]

    def get_key_material(self, key_id: str) -> bytes:
        # 32 bytes = AES-256
        return b"\x01" * 32
