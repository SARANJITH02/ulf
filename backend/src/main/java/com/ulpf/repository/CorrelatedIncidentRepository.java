package com.ulpf.repository;

import com.ulpf.domain.CorrelatedIncident;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CorrelatedIncidentRepository extends JpaRepository<CorrelatedIncident, Long> {
    Optional<CorrelatedIncident> findByIncidentKey(String incidentKey);
    List<CorrelatedIncident> findByStatusOrderByLastSeenAtDesc(String status);
    List<CorrelatedIncident> findAllByOrderByLastSeenAtDesc();
    List<CorrelatedIncident> findTop10ByOrderByLastSeenAtDesc();
    Optional<CorrelatedIncident> findFirstByCorrelationKeyAndStatusNotOrderByLastSeenAtDesc(String correlationKey, String status);
}
