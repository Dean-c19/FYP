package org.example.cybermasterspring.service;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CityResponse;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Optional;

@Service
public class GeoIpService {

    private final DatabaseReader databaseReader;

    public GeoIpService() throws IOException {
        ClassPathResource resource = new ClassPathResource("geo/GeoLite2-City.mmdb");
        this.databaseReader = new DatabaseReader.Builder(resource.getInputStream()).build();
    }

    public Optional<GeoPoint> lookup(String ip) {
        try {
            InetAddress address = InetAddress.getByName(ip);
            CityResponse response = databaseReader.city(address);
            if (response.getLocation() == null || response.getLocation().getLatitude() == null || response.getLocation().getLongitude() == null) {
                return Optional.empty();
            }
            return Optional.of(new GeoPoint(
                    response.getLocation().getLatitude(),
                    response.getLocation().getLongitude(),
                    response.getCountry().getName()
            ));
        } catch (IOException | GeoIp2Exception e) {
            return Optional.empty();
        }
    }

    public static class GeoPoint {
        private final double lat;
        private final double lng;
        private final String country;

        public GeoPoint(double lat, double lng, String country) {
            this.lat = lat;
            this.lng = lng;
            this.country = country;
        }

        public double getLat() { return lat; }
        public double getLng() { return lng; }
        public String getCountry() { return country; }
    }
}
