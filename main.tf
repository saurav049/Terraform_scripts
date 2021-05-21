provider "google" {
  credentials = file("credentials.json")
  project     = "playground-s-11-e19a8a3d"
  region      = "us-central1"
  zone        = "us-central1-c"
}

resource "google_project_iam_custom_role" "my-instance-role1" {
  role_id     = "InstanceRole"
  title       = "My Instance Role"
  description = "my custom iam role"
  permissions = [
    "storage.objects.create", 
    "cloudkms.cryptoKeyVersions.useToEncrypt"
  ]
}

resource "google_compute_instance" "t_instance" {
  name         = "t-instance"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  tags = ["gcp"]	

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2004-lts"
    }
  }


  network_interface {
    subnetwork= google_compute_subnetwork.test_subnetwork.self_link

    access_config {
      // Ephemeral IP
    }
  }
  metadata_startup_script = file("user_data.sh")
}

resource "google_compute_network" "vpc_network" {
   name = "vpc-network"
   mtu  = 1500
   auto_create_subnetworks = false
  }
  resource "google_compute_subnetwork" "test_subnetwork" {
   name          = "demo-subnetwork"
   ip_cidr_range = "10.2.0.0/16"
   region        = "us-central1"
   network       = google_compute_network.vpc_network.id
}

resource "google_storage_bucket" "mybucket" {
  name          = "s1236bucket"
  location      = "US"
  project       = "playground-s-11-e19a8a3d"
  storage_class = "standard"

}

resource "google_storage_bucket_object" "index_html" {
  name   = "index_object"
  source = "/home/sauravk/T-demo/index.html"
  bucket = google_storage_bucket.mybucket.id
}


resource "google_compute_firewall" "modified" {
  name    = "demo-firewall"
  network = google_compute_network.vpc_network.id

  allow {
    protocol = "tcp"
    ports    = ["80", "8080", "22"]
  }
}
