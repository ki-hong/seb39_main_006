package com.codestates.seb006main.posts.controller;

import com.codestates.seb006main.dto.MultiResponseDto;
import com.codestates.seb006main.posts.dto.PostsDto;
import com.codestates.seb006main.posts.service.PostsService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/api/posts")
@RequiredArgsConstructor
public class PostsController {

    private final PostsService postsService;

    @PostMapping(consumes = { MediaType.APPLICATION_JSON_VALUE, MediaType.MULTIPART_FORM_DATA_VALUE })
    public ResponseEntity postPosts(@RequestPart(value = "key") PostsDto.Post postDto
//            , @RequestPart(value = "images", required = false) List<MultipartFile> images
                                                                                    ) throws IOException {
        // TODO: groupDto.Post를 받거나, posts와 group의 postDto를 둘 다 받는 방식.
        PostsDto.Response responseDto = postsService.createPosts(postDto);
        return new ResponseEntity<>(responseDto, HttpStatus.CREATED);
    }

    @GetMapping("/{post-id}")
    public ResponseEntity getPosts(@PathVariable("post-id") Long postId) {
        PostsDto.Response responseDto = postsService.readPosts(postId);
        return new ResponseEntity<>(responseDto, HttpStatus.OK);
    }

    @GetMapping
    public ResponseEntity getAllPosts(@PageableDefault(sort = "postId", direction = Sort.Direction.DESC) Pageable pageable) {
        PageRequest pageRequest = PageRequest.of(pageable.getPageNumber(), pageable.getPageSize(), pageable.getSort());
        MultiResponseDto responseDto = postsService.readAllPosts(pageRequest);
        return new ResponseEntity<>(responseDto, HttpStatus.OK);
    }

    @PatchMapping("/{post-id}")
    public ResponseEntity patchPosts(@PathVariable("post-id") Long postId,
                                     @RequestBody PostsDto.Patch patchDto) {
        PostsDto.Response responseDto = postsService.updatePosts(postId, patchDto);
        return new ResponseEntity<>(responseDto, HttpStatus.OK);
    }

    @DeleteMapping("/{post-id}")
    public ResponseEntity deletePosts(@PathVariable("post-id") Long postId) {
        postsService.deletePosts(postId);
        return new ResponseEntity<>("정상적으로 삭제되었습니다.", HttpStatus.NO_CONTENT);
    }
}
