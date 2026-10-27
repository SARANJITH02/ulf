package com.ulpf.repository;

import com.ulpf.domain.MerkleBatch;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface MerkleBatchRepository extends JpaRepository<MerkleBatch, String> {

    List<MerkleBatch> findAllByOrderByCreatedAtDesc();

    Optional<MerkleBatch> findById(String id);

    Optional<MerkleBatch> findFirstByOrderByCreatedAtDesc();

    List<MerkleBatch> findByCreatedAtBetweenOrderByCreatedAtDesc(Instant start, Instant end);

    @Query("SELECT COALESCE(SUM(b.eventCount), 0) FROM MerkleBatch b")
    long sumAllBatchedEvents();
}
