package io.authgate.domain.model;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * OIDC UserInfo response — standard identity claims about the authenticated user.
 *
 * <p>Only {@code subject} ("sub") is required per the OIDC Core specification.
 * All other claims are nullable. Non-standard claims are available via {@link #customClaims()}.</p>
 *
 * <p>{@link #toString()} masks PII — safe for logging.</p>
 */
public final class UserInfo {

    private final String subject;
    private final String email;
    private final Boolean emailVerified;
    private final String name;
    private final String givenName;
    private final String familyName;
    private final String preferredUsername;
    private final String picture;
    private final String locale;
    private final String zoneinfo;
    private final String phoneNumber;
    private final Boolean phoneNumberVerified;
    private final Instant updatedAt;
    private final Map<String, Object> customClaims;

    public UserInfo(String subject,
                    String email,
                    Boolean emailVerified,
                    String name,
                    String givenName,
                    String familyName,
                    String preferredUsername,
                    String picture,
                    String locale,
                    String zoneinfo,
                    String phoneNumber,
                    Boolean phoneNumberVerified,
                    Instant updatedAt,
                    Map<String, Object> customClaims) {
        Objects.requireNonNull(subject, "subject (sub) must not be null");
        if (subject.isBlank()) {
            throw new IllegalArgumentException("subject (sub) must not be blank");
        }
        this.subject = subject;
        this.email = email;
        this.emailVerified = emailVerified;
        this.name = name;
        this.givenName = givenName;
        this.familyName = familyName;
        this.preferredUsername = preferredUsername;
        this.picture = picture;
        this.locale = locale;
        this.zoneinfo = zoneinfo;
        this.phoneNumber = phoneNumber;
        this.phoneNumberVerified = phoneNumberVerified;
        this.updatedAt = updatedAt;
        this.customClaims = customClaims != null
                ? Collections.unmodifiableMap(customClaims)
                : Map.of();
    }

    public String subject()              { return subject; }
    public String email()                { return email; }
    public Boolean emailVerified()       { return emailVerified; }
    public String name()                 { return name; }
    public String givenName()            { return givenName; }
    public String familyName()           { return familyName; }
    public String preferredUsername()     { return preferredUsername; }
    public String picture()              { return picture; }
    public String locale()               { return locale; }
    public String zoneinfo()             { return zoneinfo; }
    public String phoneNumber()          { return phoneNumber; }
    public Boolean phoneNumberVerified() { return phoneNumberVerified; }
    public Instant updatedAt()           { return updatedAt; }
    public Map<String, Object> customClaims() { return customClaims; }

    @Override
    public String toString() {
        return "UserInfo[sub=***]";
    }
}
