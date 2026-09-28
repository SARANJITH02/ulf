package com.ulpf.repository;

import com.ulpf.domain.DriftAlert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface DriftAlertRepository extends JpaRepository<DriftAlert, Long> {

    List<DriftAlert> findAllByOrderByDetectedAtDesc();

    List<DriftAlert> findByStatusOrderByDetectedAtDesc(String status);

    List<DriftAlert> findByParserNameOrderByDetectedAtDesc(String parserName);

    Optional<DriftAlert> findFirstByParserNameAndStatus(String parserName, String status);

    long countByStatus(String status);
}
