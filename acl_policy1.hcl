policy {
  acl = "read"
  node {
    name   = "test"
    policy = "write"
  }
  node_prefix {
    name   = "windows"
    policy = "write"
  }
  service {
    name   = "Database"
    policy = "write"
  }
  service_prefix {
    name   = "APIService"
    policy = "read"
  }
}

