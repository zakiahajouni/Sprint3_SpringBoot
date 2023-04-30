package com.zakia.Motors.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import groovyjarjarantlr4.v4.runtime.misc.NotNull;
import jakarta.persistence.*;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Type {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
private Long id;
    @NotNull

private String nameType;
    @NotNull

    private String description;
    @JsonIgnore
    @OneToMany(mappedBy = "type")
    private List<Motor> motors;


}
