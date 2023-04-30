package com.zakia.Motors.entities;

import groovyjarjarantlr4.v4.runtime.misc.NotNull;
import jakarta.persistence.*;
import jakarta.validation.constraints.PastOrPresent;
import jakarta.validation.constraints.Size;
import org.springframework.format.annotation.DateTimeFormat;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import java.util.Date;


@Entity

public class Motor {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long idMotor;

    @NotNull
    @Size(min = 4,max = 15)
    private String nameMotor;


    @Min(value = 10)
    @Max(value = 10000)
    private Double priceMotor;

    @Temporal(TemporalType.DATE)
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    @PastOrPresent
    private Date dateCreation;

    @Min(value = 80)
    @Max(value = 400)
    private int maxSpeedMotor;


    @NotNull
    @Size(min = 4,max = 15)
    private String colorMotor;
    @ManyToOne
    private Type type;

    public Motor() {
    }

    public Motor(Long idMotor, String nameMotor, Double priceMotor, Date dateCreation, int maxSpeedMotor, String colorMotor, Type type) {
        this.idMotor = idMotor;
        this.nameMotor = nameMotor;
        this.priceMotor = priceMotor;
        this.dateCreation = dateCreation;
        this.maxSpeedMotor = maxSpeedMotor;
        this.colorMotor = colorMotor;
        this.type = type;
    }

    public Long getIdMotor() {
        return idMotor;
    }

    public String getNameMotor() {
        return nameMotor;
    }

    public Double getPriceMotor() {
        return priceMotor;
    }

    public Date getDateCreation() {
        return dateCreation;
    }

    public int getMaxSpeedMotor() {
        return maxSpeedMotor;
    }

    public String getColorMotor() {
        return colorMotor;
    }

    public Type getType() {
        return type;
    }

    public void setIdMotor(Long idMotor) {
        this.idMotor = idMotor;
    }

    public void setNameMotor(String nameMotor) {
        this.nameMotor = nameMotor;
    }

    public void setPriceMotor(Double priceMotor) {
        this.priceMotor = priceMotor;
    }

    public void setDateCreation(Date dateCreation) {
        this.dateCreation = dateCreation;
    }

    public void setMaxSpeedMotor(int maxSpeedMotor) {
        this.maxSpeedMotor = maxSpeedMotor;
    }

    public void setColorMotor(String colorMotor) {
        this.colorMotor = colorMotor;
    }

    public void setType(Type type) {
        this.type = type;
    }

    @Override
    public String toString() {
        return "Motor{" +
                "idMotor=" + idMotor +
                ", nameMotor='" + nameMotor + '\'' +
                ", priceMotor=" + priceMotor +
                ", dateCreation=" + dateCreation +
                ", maxSpeedMotor=" + maxSpeedMotor +
                ", colorMotor='" + colorMotor + '\'' +
                ", type=" + type +
                '}';
    }
}
