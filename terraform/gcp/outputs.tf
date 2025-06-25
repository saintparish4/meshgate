output "agent_internal_ip" {
  value = google_compute_instance.agent.network_interface[0].network_ip
}
