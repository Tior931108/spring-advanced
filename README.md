# 📋 SPRING ADVANCED

Spring Boot를 활용한 일정 관리 애플리케이션을 리팩토링 하는 과제입니다. 
사용자 인증, 일정 CRUD, 댓글, 담당자 관리 기능을 제공합니다.
시간 관계상 필수 과제만 완료하였으며, 추후 도전과제 추가할 예정입니다.

---

## 📚 목차
- [기술 스택](#-기술-스택)
- [주요 기능](#-주요-기능)
- [레벨별 구현 내용](#-레벨별-구현-내용)
- [API 명세](#-api-명세)
- [ERD](#-erd)
- [트러블슈팅](#-트러블슈팅)
- [실행 방법](#-실행-방법)

---

## 🛠 기술 스택

### Backend
- **Java 17**
- **Spring Boot 3.x**
- **Spring Data JPA**
- **Spring Security**
- **JWT (JSON Web Token)**

### Database
- **MySQL 8.0**

### Build Tool
- **Gradle**

### Test
- **JUnit 5**
- **Mockito**

---

## 🎯 주요 기능

### 1. 사용자 관리
- 회원가입 / 로그인 (JWT 기반 인증)
- 비밀번호 변경
- 권한별 접근 제어 (USER, ADMIN)

### 2. 일정 관리
- 일정 생성 / 조회 / 수정 / 삭제
- 페이징 처리를 통한 일정 목록 조회
- 날씨 정보 자동 저장

### 3. 댓글 관리
- 댓글 작성 / 조회 / 수정 / 삭제
- 일정별 댓글 목록 조회

### 4. 담당자 관리
- 일정에 담당자 추가
- 담당자 목록 조회
- 담당자 삭제

---

## 📝 레벨별 구현 내용

### 📌 Lv 0. 코드 개선 퀴즈 - AuthUserArgumentResolver

#### 🔴 문제점
- `AuthUserArgumentResolver`에서 JWT 필터가 설정한 attribute 값을 가져올 때 **null 체크가 없어** NullPointerException 발생 가능
- 인증이 실패하거나 토큰이 없는 경우 처리 로직 부재

#### ✅ 해결
```java
@Override
public Object resolveArgument(
        @Nullable MethodParameter parameter,
        @Nullable ModelAndViewContainer mavContainer,
        NativeWebRequest webRequest,
        @Nullable WebDataBinderFactory binderFactory
) {
    HttpServletRequest request = (HttpServletRequest) webRequest.getNativeRequest();

    // JwtFilter에서 set한 attribute 가져오기
    Long userId = (Long) request.getAttribute("userId");
    String email = (String) request.getAttribute("email");
    String userRoleString = (String) request.getAttribute("userRole");

    // Null 체크 추가
    if (userId == null || email == null || userRoleString == null) {
        throw new AuthException("인증 정보가 올바르지 않습니다.");
    }

    UserRole userRole = UserRole.of(userRoleString);
    return new AuthUser(userId, email, userRole);
}
```

**개선 효과:**
- 인증 정보 누락 시 명확한 예외 메시지 제공
- NullPointerException 방지
- 더 안전한 인증 처리

---

### 📌 Lv 1. 코드 개선 퀴즈 - Early Return 패턴

#### 1️⃣ AuthService - signup()

##### 🔴 문제점
```java
// 비용이 큰 암호화 작업을 먼저 실행
String encodedPassword = passwordEncoder.encode(signupRequest.getPassword());

// 그 다음에 이메일 중복 체크
if (userRepository.existsByEmail(signupRequest.getEmail())) {
    throw new InvalidRequestException("이미 존재하는 이메일입니다.");
}
```
- 이메일이 중복되면 **이미 실행된 암호화 작업이 낭비**됨
- 암호화는 의도적으로 느린 연산이므로 성능 저하

##### ✅ 해결 (Early Return 적용)
```java
@Transactional
public SignupResponse signup(SignupRequest signupRequest) {
    // 1. 먼저 검증 (빠른 작업)
    if (userRepository.existsByEmail(signupRequest.getEmail())) {
        throw new InvalidRequestException("이미 존재하는 이메일입니다.");
    }
    
    // 2️. 검증 통과 후 비용이 큰 작업 수행
    String encodedPassword = passwordEncoder.encode(signupRequest.getPassword());
    UserRole userRole = UserRole.of(signupRequest.getUserRole());
    
    User newUser = new User(
            signupRequest.getEmail(),
            encodedPassword,
            userRole
    );
    User savedUser = userRepository.save(newUser);
    
    String bearerToken = jwtUtil.createToken(savedUser.getId(), savedUser.getEmail(), userRole);
    
    return new SignupResponse(bearerToken);
}
```

**개선 효과:**
- 실패 시 불필요한 암호화 연산 방지 (약 500ms 절약)
- 빠른 실패(Fail Fast) 전략으로 성능 향상

---

#### 2️⃣ WeatherClient - getTodayWeather()

##### 🔴 문제점
```java
if (!HttpStatus.OK.equals(responseEntity.getStatusCode())) {
    throw new ServerException("날씨 데이터를 가져오는데 실패했습니다.");
} else {  // 불필요한 else
    if (weatherArray == null || weatherArray.length == 0) {
        throw new ServerException("날씨 데이터가 없습니다.");
    }
}
```
- 불필요한 `else` 블록 사용
- 중첩된 `if`문으로 가독성 저하

##### ✅ 해결 (불필요한 if-else 제거)
```java
public String getTodayWeather() {
    ResponseEntity<WeatherDto[]> responseEntity =
            restTemplate.getForEntity(buildWeatherApiUri(), WeatherDto[].class);

    // 1. 상태 코드 검증
    if (!HttpStatus.OK.equals(responseEntity.getStatusCode())) {
        throw new ServerException("날씨 데이터를 가져오는데 실패했습니다.");
    }

    // 2️. 데이터 존재 여부 검증
    WeatherDto[] weatherArray = responseEntity.getBody();
    if (weatherArray == null || weatherArray.length == 0) {
        throw new ServerException("날씨 데이터가 없습니다.");
    }

    // 3️. 오늘 날짜의 날씨 검색
    String today = getCurrentDate();
    for (WeatherDto weatherDto : weatherArray) {
        if (today.equals(weatherDto.getDate())) {
            return weatherDto.getWeather();
        }
    }

    throw new ServerException("오늘에 해당하는 날씨 데이터를 찾을 수 없습니다.");
}
```

**개선 효과:**
- Guard Clause 패턴으로 가독성 향상
- 중첩 제거로 코드 복잡도 감소
- 명확한 검증 흐름 (상태 코드 → 데이터 존재 → 날씨 검색)

---

### 📌 Lv 2. 코드 개선 퀴즈 - DTO 검증

#### 🔴 문제점
- **Service 계층**에서 DTO 검증 로직 처리
- 책임 분리 원칙 위반 (검증은 API 계층의 책임)

```java
// Service에서 검증
@Transactional
public void changePassword(Long userId, UserChangePasswordRequest request) {
    if (request.getNewPassword().length() < 8 ||
        !request.getNewPassword().matches(".*\\d.*") ||
        !request.getNewPassword().matches(".*[A-Z].*")) {
        throw new InvalidRequestException("새 비밀번호는 8자 이상이어야 하고, 숫자와 대문자를 포함해야 합니다.");
    }
    // ... 비즈니스 로직
}
```

#### ✅ 해결 (검증을 API 계층으로 이동)

##### 1. DTO에 검증 어노테이션 추가
```java
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class UserChangePasswordRequest {
    
    @NotBlank(message = "기존 비밀번호를 입력해주세요.")
    private String oldPassword;
    
    @NotBlank(message = "새 비밀번호를 입력해주세요.")
    @Size(min = 8, message = "새 비밀번호는 8자 이상이어야 합니다.")
    @Pattern(
        regexp = "^(?=.*\\d)(?=.*[A-Z]).+$",
        message = "새 비밀번호는 숫자와 대문자를 포함해야 합니다."
    )
    private String newPassword;
}
```

##### 2. Controller에서 @Valid 적용
```java
@PutMapping("/{userId}")
public void changePassword(
        @PathVariable Long userId,
        @Valid @RequestBody UserChangePasswordRequest request
) {
    userService.changePassword(userId, request);
}
```

##### 3. Service는 비즈니스 로직에만 집중
```java
@Transactional
public void changePassword(Long userId, UserChangePasswordRequest request) {
    // DTO 검증은 이미 Controller에서 처리됨
    
    User user = userRepository.findById(userId)
            .orElseThrow(() -> new InvalidRequestException("사용자를 찾을 수 없습니다."));
    
    // 기존 비밀번호 확인
    if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
        throw new InvalidRequestException("기존 비밀번호가 일치하지 않습니다.");
    }
    
    // 새 비밀번호로 변경
    String encodedNewPassword = passwordEncoder.encode(request.getNewPassword());
    user.changePassword(encodedNewPassword);
}
```

**개선 효과:**
- 계층별 책임 명확화 (DTO: 검증, Service: 비즈니스 로직)
- 검증 규칙 재사용 가능
- 테스트 용이성 향상

---

### 📌 Lv 3. N+1 문제 해결

#### 🔴 문제점
- `getTodos()` 메서드에서 모든 Todo를 조회할 때, 각 Todo의 User 정보를 가져오면서 **N+1 쿼리 발생**

```sql
-- 1. Todo 전체 조회 (1번 쿼리)
SELECT * FROM todos ORDER BY modified_at DESC LIMIT 10;

-- 2. 각 Todo마다 User 조회 (N번 쿼리)
SELECT * FROM users WHERE id = 1;
SELECT * FROM users WHERE id = 2;
SELECT * FROM users WHERE id = 3;
...
```

#### ✅ 해결 (@EntityGraph 또는 Fetch Join)

##### 방법 1: @EntityGraph 사용
```java
public interface TodoRepository extends JpaRepository<Todo, Long> {
    
    @EntityGraph(attributePaths = {"user"})
    @Query("SELECT t FROM Todo t ORDER BY t.modifiedAt DESC")
    Page<Todo> findAllByOrderByModifiedAtDesc(Pageable pageable);
    
    @EntityGraph(attributePaths = {"user"})
    Optional<Todo> findById(Long id);
}
```

##### 방법 2: JPQL Fetch Join (Count Query 분리)
```java
public interface TodoRepository extends JpaRepository<Todo, Long> {
    
    @Query(
        value = "SELECT t FROM Todo t LEFT JOIN FETCH t.user u ORDER BY t.modifiedAt DESC",
        countQuery = "SELECT COUNT(t) FROM Todo t"  // Count 쿼리 분리
    )
    Page<Todo> findAllByOrderByModifiedAtDesc(Pageable pageable);
    
    @Query("SELECT t FROM Todo t LEFT JOIN FETCH t.user WHERE t.id = :todoId")
    Optional<Todo> findByIdWithUser(@Param("todoId") Long todoId);
}
```

**개선 효과:**
- 쿼리 횟수: N+1번 → 1번
- 데이터베이스 부하 대폭 감소
- 응답 속도 향상

**생성되는 SQL:**
```sql
-- 한 번의 쿼리로 모든 데이터 조회
SELECT t.*, u.*
FROM todos t
LEFT JOIN users u ON t.user_id = u.id
ORDER BY t.modified_at DESC
LIMIT 10;
```

---

### 📌 Lv 4. 테스트 코드 작성

#### 1️⃣ Manager 조회 시 Todo가 없는 경우 예외 테스트

##### 원래 코드 (NPE 발생)
```java
@Test
public void manager_목록_조회_시_Todo가_없다면_NPE_예외를_던진다() {
    // given
    long todoId = 1L;
    given(todoRepository.findById(todoId)).willReturn(Optional.empty());
    
    // when & then - ❌ InvalidRequestException 발생
    assertThrows(InvalidRequestException.class, 
        () -> managerService.getManagers(todoId));
}
```

##### 수정 (Invalid)
```java
@Test
  public void manager_목록_조회_시_Todo가_없다면_INVALID_예외를_던진다() {
      // given
      long todoId = 1L;
      given(todoRepository.findById(todoId)).willReturn(Optional.empty());
      
      // when & then
      InvalidRequestException exception = assertThrows(
          InvalidRequestException.class,
          () -> managerService.getManagers(todoId)
      );
      
      assertEquals("Todo not found", exception.getMessage());
}
```

---

#### 2️⃣ Todo의 User가 null인 경우 예외 테스트

##### 서비스 로직 수정 (null 방어)
```java
@Transactional
public ManagerSaveResponse saveManager(
        AuthUser authUser, 
        long todoId, 
        ManagerSaveRequest managerSaveRequest
) {
    User user = User.fromAuthUser(authUser);
    Todo todo = todoRepository.findById(todoId)
            .orElseThrow(() -> new InvalidRequestException("Todo not found"));
    
    // user가 null인지 체크
    if (todo.getUser() == null || 
        !ObjectUtils.nullSafeEquals(user.getId(), todo.getUser().getId())) {
        throw new InvalidRequestException("일정을 생성한 유저만 담당자를 지정할 수 있습니다.");
    }
    
    // ... 나머지 로직
}
```

##### 테스트 코드
```java
@Test
void todo의_user가_null인_경우_예외가_발생한다() {
    // given
    AuthUser authUser = new AuthUser(1L, "a@a.com", UserRole.USER);
    long todoId = 1L;
    long managerUserId = 2L;
    
    Todo todo = new Todo();
    ReflectionTestUtils.setField(todo, "user", null);  // user를 null로 설정
    
    ManagerSaveRequest managerSaveRequest = new ManagerSaveRequest(managerUserId);
    
    given(todoRepository.findById(todoId)).willReturn(Optional.of(todo));
    
    // when & then
    InvalidRequestException exception = assertThrows(
        InvalidRequestException.class,
        () -> managerService.saveManager(authUser, todoId, managerSaveRequest)
    );
    
    assertEquals("일정을 생성한 유저만 담당자를 지정할 수 있습니다.", exception.getMessage());
}
```

---

#### 3️⃣ PasswordEncoder 테스트

```java
@SpringBootTest
public class PasswordEncoderTest {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void matches_메서드가_정상적으로_동작한다() {
        // given
        String rawPassword = "testPassword";
        String encodedPassword = passwordEncoder.encode(rawPassword);

        // when
        boolean matches = passwordEncoder.matches(rawPassword, encodedPassword);
        //                                        ↑ 원본      ↑ 암호화된 것

        // then
        assertTrue(matches);
    }
}
```

**테스트 패턴:**
- **Given-When-Then** 구조로 작성
- Mock 객체를 활용한 단위 테스트
- 예외 케이스까지 검증

---

## 📡 API 명세

### 인증 (Authentication)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/signup` | 회원가입 | ❌ |
| POST | `/auth/signin` | 로그인 | ❌ |

### 사용자 (User)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| PUT | `/users/{userId}` | 비밀번호 변경 | ✅ |

### 일정 (Todo)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/todos` | 일정 생성 | ✅ |
| GET | `/todos` | 일정 목록 조회 (페이징) | ✅ |
| GET | `/todos/{todoId}` | 일정 단건 조회 | ✅ |
| PUT | `/todos/{todoId}` | 일정 수정 | ✅ |
| DELETE | `/todos/{todoId}` | 일정 삭제 | ✅ |

### 댓글 (Comment)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/todos/{todoId}/comments` | 댓글 작성 | ✅ |
| GET | `/todos/{todoId}/comments` | 댓글 목록 조회 | ✅ |
| PUT | `/comments/{commentId}` | 댓글 수정 | ✅ |
| DELETE | `/comments/{commentId}` | 댓글 삭제 | ✅ |

### 담당자 (Manager)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/todos/{todoId}/managers` | 담당자 추가 | ✅ |
| GET | `/todos/{todoId}/managers` | 담당자 목록 조회 | ✅ |
| DELETE | `/todos/{todoId}/managers/{managerId}` | 담당자 삭제 | ✅ |

---

## 🗄 ERD

```
┌─────────────┐
│    users    │
├─────────────┤
│ id          │ PK
│ email       │
│ password    │
│ user_role   │
│ created_at  │
│ modified_at │
└──────┬──────┘
       │
       │ 1:N
       │
┌──────┴──────┐
│    todos    │
├─────────────┤
│ id          │ PK
│ title       │
│ contents    │
│ weather     │
│ user_id     │ FK
│ created_at  │
│ modified_at │
└──────┬──────┘
       │
       ├──────┐
       │ 1:N  │ 1:N
       │      │
┌──────┴─────┐│  ┌──────────────┐
│  comments  │└──│   managers   │
├────────────┤   ├──────────────┤
│ id         │PK │ id           │ PK
│ contents   │   │ user_id      │ FK
│ user_id    │FK │ todo_id      │ FK
│ todo_id    │FK │ created_at   │
│ created_at │   │ modified_at  │
│ modified_at│   └──────────────┘
└────────────┘
```

---

## 🔧 트러블슈팅

### 1. N+1 문제

**문제:** 일정 목록 조회 시 각 일정마다 User 정보를 조회하면서 쿼리가 N+1번 발생

**해결:**
- `@EntityGraph(attributePaths = {"user"})`로 Fetch Join 적용
- 또는 JPQL에서 `LEFT JOIN FETCH` 사용
- Count Query 분리로 페이징 최적화

**결과:** 쿼리 횟수 N+1번 → 1번으로 감소

---

### 2. PasswordEncoder 파라미터 순서 실수

**문제:** `passwordEncoder.matches(encodedPassword, rawPassword)` 순서 잘못 사용

**해결:** `passwordEncoder.matches(rawPassword, encodedPassword)` 순서 교정

**교훈:** 
```java
// ✅ 올바른 순서
boolean matches = passwordEncoder.matches(
    rawPassword,      // 1. 원본 비밀번호
    encodedPassword   // 2. 암호화된 비밀번호
);
```

---

### 3. Early Return을 적용한 성능 개선

**문제:** 비용이 큰 작업(암호화)을 검증 전에 실행하여 불필요한 연산 발생

**해결:** 
1. 빠른 검증(이메일 중복 체크)을 먼저 실행
2. 검증 통과 후 비용이 큰 작업(암호화) 실행

**결과:** 실패 케이스에서 약 500ms 절약

---

### 4. Null 안전성 개선

**문제:** 
- `AuthUserArgumentResolver`에서 null 체크 없이 attribute 사용
- `ManagerService`에서 `todo.getUser()`가 null인 경우 NPE 발생

**해결:**
```java
// AuthUserArgumentResolver
if (userId == null || email == null || userRoleString == null) {
    throw new AuthException("인증 정보가 올바르지 않습니다.");
}

// ManagerService
if (todo.getUser() == null || !ObjectUtils.nullSafeEquals(...)) {
    throw new InvalidRequestException("일정을 생성한 유저만 담당자를 지정할 수 있습니다.");
}
```

**교훈:** 항상 null 가능성을 고려한 방어적 프로그래밍 필요

---

## 🚀 실행 방법

### 1. 사전 요구사항
- Java 17 이상
- MySQL 8.0
- Gradle

### 2. 데이터베이스 설정

### 3. application.yml 설정

### 4. 프로젝트 실행

### 5. API 테스트

---

## 📌 주요 학습 내용

### 1. 코드 품질 개선
- **Early Return 패턴**: 검증 로직을 앞으로 배치하여 성능 향상
- **Guard Clause**: 중첩된 if문 제거로 가독성 향상
- **책임 분리**: 검증은 API 계층, 비즈니스 로직은 Service 계층

### 2. 성능 최적화
- **N+1 문제 해결**: @EntityGraph, Fetch Join 활용
- **Count Query 분리**: 페이징 처리 최적화

### 3. 안전성 강화
- **Null 체크**: 방어적 프로그래밍으로 NPE 방지
- **예외 처리**: 명확한 예외 메시지로 디버깅 용이

### 4. 테스트
- **Given-When-Then 패턴**: 체계적인 테스트 작성
- **Mock 활용**: 단위 테스트를 통한 검증
- **예외 케이스**: 정상/비정상 케이스 모두 테스트

---

## 👤 개발자

Spring 심화 프로젝트 8조 팔방미인즈 정용준

도전과제 리팩토링 예정입니다. 
