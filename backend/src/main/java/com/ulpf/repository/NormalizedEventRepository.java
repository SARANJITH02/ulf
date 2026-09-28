package com.ulpf.repository;

import com.ulpf.domain.NormalizedEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface NormalizedEventRepository extends JpaRepository<NormalizedEvent, Long> {
    Optional<NormalizedEvent> findByEventId(String eventId);
    Optional<NormalizedEvent> findByRawEventId(String rawEventId);

    List<NormalizedEvent> findTop50ByOrderByProcessedAtDesc();

    @Query("SELECT e FROM NormalizedEvent e WHERE " +
           "(:sourceIp IS NULL OR e.sourceIp = :sourceIp) AND " +
           "(:destinationIp IS NULL OR e.destinationIp = :destinationIp) AND " +
           "(:action IS NULL OR LOWER(e.action) = LOWER(:action)) AND " +
           "(:severity IS NULL OR LOWER(e.severity) = LOWER(:severity)) AND " +
           "(:format IS NULL OR e.format = :format) AND " +
           "(:parserName IS NULL OR e.parserName = :parserName) AND " +
           "(:startTime IS NULL OR e.timestampUtc >= :startTime) AND " +
           "(:endTime IS NULL OR e.timestampUtc <= :endTime)")
    Page<NormalizedEvent> searchEvents(
            @Param("sourceIp") String sourceIp,
            @Param("destinationIp") String destinationIp,
            @Param("action") String action,
            @Param("severity") String severity,
            @Param("format") String format,
            @Param("parserName") String parserName,
            @Param("startTime") Instant startTime,
            @Param("endTime") Instant endTime,
            Pageable pageable);

    List<NormalizedEvent> findByMerkleBatchId(String merkleBatchId);

    List<NormalizedEvent> findTop500ByParserNameOrderByProcessedAtDesc(String parserName);

    List<NormalizedEvent> findByProcessedAtAfterAndParserName(Instant since, String parserName);

    List<NormalizedEvent> findByProcessedAtAfter(Instant since);

    @Query("SELECT COUNT(e) FROM NormalizedEvent e WHERE e.processedAt >= :since")
    long countEventsSince(@Param("since") Instant since);
}
