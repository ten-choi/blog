const fs = require("fs");
const path = require("path");
const frontMatter = require("front-matter");

/**
 * 마크다운 파일의 Front Matter를 검증합니다.
 * @param {string} filePath - 검증할 마크다운 파일 경로
 * @returns {Object} 검증 결과 {valid, errors, warnings, data}
 */
function validateFrontMatter(filePath) {
  try {
    // 파일 읽기
    const fileContent = fs.readFileSync(filePath, "utf8");

    // Front Matter 파싱
    const { attributes, body } = frontMatter(fileContent);

    const errors = [];
    const warnings = [];

    // 필수 필드 검증
    if (!attributes.title) {
      errors.push("title이 없습니다 - 게시물에 제목을 추가하세요");
    }

    if (attributes.published === undefined) {
      warnings.push("published 필드가 없습니다 - 기본값은 false(초안)입니다");
    }

    if (!attributes.description) {
      warnings.push(
        "description이 없습니다 - 게시물에 간단한 설명을 추가하는 것이 좋습니다"
      );
    }

    if (!attributes.tags) {
      warnings.push(
        "tags가 없습니다 - 검색과 분류를 위해 태그를 추가하는 것이 좋습니다"
      );
    } else {
      // 태그 형식 검증
      const tags = attributes.tags.split(",").map((tag) => tag.trim());
      if (tags.length > 4) {
        warnings.push(
          "태그가 4개를 초과합니다 - DEV.to는 최대 4개의 태그를 허용합니다"
        );
      }
    }

    // 본문 콘텐츠 검증
    if (body.trim().length < 50) {
      warnings.push(
        "본문 내용이 너무 짧습니다 - 더 많은 콘텐츠를 추가하는 것이 좋습니다"
      );
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      data: {
        filePath,
        fileName: path.basename(filePath),
        title: attributes.title,
        published: attributes.published || false,
        description: attributes.description,
        tags: attributes.tags,
        bodyLength: body.length,
      },
    };
  } catch (error) {
    if (error.message.includes("front-matter")) {
      return {
        valid: false,
        errors: ["Front Matter 형식이 잘못되었습니다. YAML 형식을 확인하세요."],
        warnings: [],
        data: { filePath, fileName: path.basename(filePath) },
      };
    }

    return {
      valid: false,
      errors: [`파일 검증 중 오류 발생: ${error.message}`],
      warnings: [],
      data: { filePath, fileName: path.basename(filePath) },
    };
  }
}

/**
 * posts 디렉토리의 모든 마크다운 파일을 검증합니다.
 */
function validateAllPosts() {
  const postsDir = path.join(__dirname, "posts");
  let allValid = true;

  try {
    const files = fs.readdirSync(postsDir);
    for (const file of files) {
      if (file.endsWith(".md")) {
        const filePath = path.join(postsDir, file);
        const result = validateFrontMatter(filePath);

        console.log(`\n검증: ${file}`);

        if (result.errors.length > 0) {
          console.log("❌ 오류:");
          result.errors.forEach((err) => console.log(`  - ${err}`));
          allValid = false;
        } else {
          console.log("✅ 오류 없음");
        }

        if (result.warnings.length > 0) {
          console.log("⚠️ 경고:");
          result.warnings.forEach((warn) => console.log(`  - ${warn}`));
        }

        console.log("📄 정보:");
        console.log(`  - 제목: ${result.data.title || "없음"}`);
        console.log(`  - 공개 여부: ${result.data.published}`);
        console.log(`  - 태그: ${result.data.tags || "없음"}`);
        console.log(`  - 본문 길이: ${result.data.bodyLength || 0} 자`);
      }
    }

    console.log("\n검증 요약:");
    if (allValid) {
      console.log("✅ 모든 게시물이 DEV.to에 게시할 준비가 되었습니다!");
    } else {
      console.log("❌ 일부 게시물에 오류가 있습니다. 위의 오류를 수정하세요.");
    }
  } catch (error) {
    console.error("게시물 검증 중 오류 발생:", error.message);
    process.exit(1);
  }
}

/**
 * 새 게시물 템플릿을 생성합니다.
 * @param {string} title - 게시물 제목
 */
function createNewPost(title) {
  if (!title) {
    console.error("오류: 게시물 제목을 입력하세요.");
    console.log('사용법: node validate.js create "게시물 제목"');
    process.exit(1);
  }

  const postsDir = path.join(__dirname, "posts");

  // 디렉토리가 없으면 생성
  if (!fs.existsSync(postsDir)) {
    fs.mkdirSync(postsDir, { recursive: true });
  }

  // 파일 이름 생성 (제목에서 특수문자 제거 및 공백을 하이픈으로 변경)
  const fileName =
    title
      .toLowerCase()
      .replace(/[^\w\s가-힣]/g, "")
      .replace(/\s+/g, "-")
      .replace(/[가-힣]/g, (char) => {
        const codePoint = char.charCodeAt(0);
        return codePoint.toString(16);
      }) + ".md";

  const filePath = path.join(postsDir, fileName);

  // 현재 날짜
  const today = new Date();
  const dateStr = today.toISOString().split("T")[0];

  // 템플릿 내용
  const content = `---
title: ${title}
published: false
description: 
tags: 
cover_image: 
series: 
---

# ${title}

작성일: ${dateStr}

여기에 본문 내용을 작성하세요...

## 소제목

본문 내용...

## 코드 예제

\`\`\`javascript
// 코드 예제
function hello() {
  console.log("안녕하세요!");
}
\`\`\`

## 결론

마무리 내용...
`;

  // 파일 생성
  fs.writeFileSync(filePath, content, "utf8");
  console.log(`✅ 새 게시물이 생성되었습니다: ${fileName}`);
  console.log(`📝 파일 경로: ${filePath}`);
}

// 명령줄 인수 처리
function main() {
  const command = process.argv[2];

  if (command === "create") {
    createNewPost(process.argv[3]);
  } else if (command === "validate") {
    validateAllPosts();
  } else {
    // 기본: 모든 게시물 검증
    validateAllPosts();
    console.log(
      '\n새 게시물을 생성하려면: node validate.js create "게시물 제목"'
    );
  }
}

main();
