package org.example.cybermasterspring.dto;

public class ThreatEvent {
    private String ip;
    private double lat;
    private double lng;
    private String country;
    private int score;

    public ThreatEvent() {
    }

    public ThreatEvent(String ip, double lat, double lng, String country, int score) {
        this.ip = ip;
        this.lat = lat;
        this.lng = lng;
        this.country = country;
        this.score = score;
    }

    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }
    public double getLat() { return lat; }
    public void setLat(double lat) { this.lat = lat; }
    public double getLng() { return lng; }
    public void setLng(double lng) { this.lng = lng; }
    public String getCountry() { return country; }
    public void setCountry(String country) { this.country = country; }
    public int getScore() { return score; }
    public void setScore(int score) { this.score = score; }
}
