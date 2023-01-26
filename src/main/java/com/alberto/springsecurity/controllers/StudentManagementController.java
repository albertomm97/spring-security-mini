package com.alberto.springsecurity.controllers;

import com.alberto.springsecurity.models.Student;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

import java.util.List;

@RestController
@RequestMapping("/management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = List.of(
            new Student(1L, "alberto"),
            new Student(2L, "juanan"),
            new Student(3L, "dani")
    );

    @GetMapping("")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAIN')")
    public ResponseEntity<List<Student>> getAllStudents() {
        return ResponseEntity.status(HttpStatus.OK).body(STUDENTS);
    }

    @PostMapping("")
    @PreAuthorize("hasAuthority('student:write')")
    public ResponseEntity<Student> registerNewStudent(@RequestBody Student student) {

        STUDENTS.add(student);

        return ResponseEntity.status(HttpStatus.CREATED).body(student);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('student:write')")
    public ResponseEntity<Student> deleteStudent(@PathVariable(name = "id") Long id) {
        var student = STUDENTS.stream()
                .filter(stdnt -> stdnt.getId() == id)
                .findFirst();

        if (!student.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }

        STUDENTS.removeIf(s -> s.getId() == id);

        return ResponseEntity.status(HttpStatus.OK).body(student.get());
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('student:write')")
    public ResponseEntity<Student> updateStudent(@PathVariable(name = "id") Long id, @RequestBody Student student) {
        var dbStudent = STUDENTS.stream()
                .filter(stdnt -> stdnt.getId() == id)
                .findFirst();

        if (!dbStudent.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }

        STUDENTS.stream().forEach(s -> {
            if (s.getId() == id) {
                s.setName(student.getName());
            }
        });

        return ResponseEntity.status(HttpStatus.OK).body(student);
    }


}
