package com.alberto.springsecurity.controllers;

import com.alberto.springsecurity.models.Student;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/students")
public class StudentController {

    private static final List<Student> STUDENTS = List.of(
            new Student(1L, "alberto"),
            new Student(2L, "juanan"),
            new Student(3L, "dani")
    );

    @GetMapping("")
    public ResponseEntity<List<Student>> getAllStudents() {
        return ResponseEntity.status(HttpStatus.OK).body(STUDENTS);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Student> getStudent(@PathVariable(name = "id") Long id) {
        Student student = STUDENTS.stream()
                .filter(std -> id.equals(std.getId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Student not found"));

        return ResponseEntity.status(HttpStatus.OK).body(student);
    }
}
