package com.zakia.Motors.repos;

import com.zakia.Motors.entities.Motor;
import com.zakia.Motors.entities.Type;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import java.util.List;
@RepositoryRestResource(path = "rest")


public interface MotorRepository extends JpaRepository<Motor, Long> {
    List<Motor> findByNameMotor(String nom);
    List<Motor> findByNameMotorContains(String nom);
    @Query("select m from Motor m where m.nameMotor like %?1 and m.priceMotor > ?2")
    List<Motor> findByNomPrix (@Param("nom") String nom, @Param("prix") Double prix);

    @Query("select m from Motor m where m.type = ?1")
    List<Motor> findByType (Type type);

    List<Motor> findByTypeId(Long id);
    List<Motor> findByOrderByNameMotorAsc();
    @Query("select m from Motor m order by m.nameMotor ASC, m.priceMotor DESC")
    List<Motor> trierMotorsNomsPrix ();






}