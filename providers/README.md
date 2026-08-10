# Custom OpenVPN providers

Place trusted `.ovpn` profiles below this directory. The container imports them read-only at `/opt/kui-providers`.

Recommended layout:

```text
providers/
└── proton/
    ├── provider.json
    ├── US/
    │   └── us-free.ovpn
    └── SG/
        └── sg-free.ovpn
```

`provider.json` applies to every profile in that directory:

```json
{
  "source": "proton",
  "username": "your-openvpn-username",
  "password": "your-openvpn-password",
  "ping": 3000,
  "score": 0
}
```

A same-name JSON file, such as `us-free.json`, overrides directory metadata:

```json
{
  "country": "US",
  "username": "profile-user",
  "password": "profile-password",
  "source": "private-provider"
}
```

Country is read from JSON first, then inferred from a two-letter directory/file token. Profiles with unsafe OpenVPN directives are rejected.
