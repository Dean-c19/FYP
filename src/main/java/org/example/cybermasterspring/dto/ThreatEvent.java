package org.example.cybermasterspring.dto;

public class ThreatEvent {
    private final String ip;
    private final double lat;
    private final double lng;
    private final String country;
    private final int score;

    public ThreatEvent(String ip, double lat, double lng, String country, int score) {
        this.ip = ip;
        this.lat = lat;
        this.lng = lng;
        this.country = country;
        this.score = score;
    }

    public String getIp() { return ip; }
    public double getLat() { return lat; }
    public double getLng() { return lng; }
    public String getCountry() { return country; }
    public int getScore() { return score; }
}
