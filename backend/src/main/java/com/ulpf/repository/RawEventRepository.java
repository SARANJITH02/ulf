package com.ulpf.repository;

import com.ulpf.domain.RawEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RawEventRepository extends JpaRepository<RawEvent, Long> {
    Optional<RawEvent> findByRawEventId(String rawEventId);
    Optional<RawEvent> findByRawHashSha256(String rawHashSha256);
}
