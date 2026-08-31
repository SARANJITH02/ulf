package com.ulpf.repository;

import com.ulpf.domain.ParserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ParserEntityRepository extends JpaRepository<ParserEntity, Long> {
    Optional<ParserEntity> findByName(String name);
    List<ParserEntity> findByActiveTrue();
}
