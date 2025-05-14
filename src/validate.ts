import fs from "fs";
import path from "path";
import frontMatter from "front-matter";

interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  data: {
    filePath: string;
    fileName: string;
    title?: string;
    published?: boolean;
    description?: string;
    tags?: string;
    bodyLength?: number;
  };
}

interface PostAttributes {
  title?: string;
  published?: boolean;
  description?: string;
  tags?: string;
  cover_image?: string;
  series?: string;
  [key: string]: any;
}

/**
 * 마크다운 파일의 Front Matter를 검증합니다.
 * @param filePath - 검증할 마크다운 파일 경로
 * @returns 검증 결과 {valid, errors, warnings, data}
 */
function validateFrontMatter(filePath: string): ValidationResult {
  try {
    // 파일 읽기
    const fileContent = fs.readFileSync(filePath, "utf8");

    // Front Matter 파싱
    const { attributes, body } = frontMatter<PostAttributes>(fileContent);

    const errors: string[] = [];
    const warnings: string[] = [];

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
      const tags = attributes.tags.split(",").map((tag: string) => tag.trim());
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
    if ((error as Error).message.includes("front-matter")) {
      return {
        valid: false,
        errors: ["Front Matter 형식이 잘못되었습니다. YAML 형식을 확인하세요."],
        warnings: [],
        data: { filePath, fileName: path.basename(filePath) },
      };
    }

    return {
      valid: false,
      errors: [`파일 검증 중 오류 발생: ${(error as Error).message}`],
      warnings: [],
      data: { filePath, fileName: path.basename(filePath) },
    };
  }
}

/**
 * posts 디렉토리의 모든 마크다운 파일을 검증합니다.
 */
function validateAllPosts(): void {
  const postsDir = path.join(__dirname, "..", "posts");
  let allValid = true;

  try {
    // 재귀적으로 모든 마크다운 파일 찾기
    const findMarkdownFiles = (dir: string): string[] => {
      let results: string[] = [];
      const list = fs.readdirSync(dir);

      list.forEach((file) => {
        const filePath = path.join(dir, file);
        const stat = fs.statSync(filePath);

        if (stat.isDirectory()) {
          // 하위 디렉토리 검색
          results = results.concat(findMarkdownFiles(filePath));
        } else if (file.endsWith(".md")) {
          // 마크다운 파일 추가
          results.push(filePath);
        }
      });

      return results;
    };

    const markdownFiles = findMarkdownFiles(postsDir);
    console.log(`검증할 마크다운 파일 ${markdownFiles.length}개를 찾았습니다.`);

    for (const filePath of markdownFiles) {
      const result = validateFrontMatter(filePath);
      displayResult(result);

      if (!result.valid) {
        allValid = false;
      }
    }

    if (allValid) {
      console.log("\n✅ 모든 게시물이 유효합니다!");
    } else {
      console.error("\n❌ 일부 게시물에 오류가 있습니다!");
      process.exit(1);
    }
  } catch (error) {
    console.error(
      `Posts 디렉토리 검증 중 오류 발생: ${(error as Error).message}`
    );
    process.exit(1);
  }
}

/**
 * 특정 마크다운 파일을 검증합니다.
 */
function validateSinglePost(filePath: string): void {
  const result = validateFrontMatter(filePath);
  displayResult(result);

  if (!result.valid) {
    process.exit(1);
  } else {
    console.log("\n✅ 게시물이 유효합니다!");
  }
}

/**
 * 검증 결과를 콘솔에 출력합니다.
 */
function displayResult(result: ValidationResult): void {
  console.log(`\n파일: ${result.data.fileName}`);
  console.log("------------------------");

  if (result.data.title) {
    console.log(`제목: ${result.data.title}`);
  }

  console.log(`공개 여부: ${result.data.published ? "예" : "아니오"}`);

  if (result.errors.length > 0) {
    console.log("\n❌ 오류:");
    result.errors.forEach((error) => console.log(`- ${error}`));
  }

  if (result.warnings.length > 0) {
    console.log("\n⚠️ 경고:");
    result.warnings.forEach((warning) => console.log(`- ${warning}`));
  }
}

/**
 * 새 게시물 템플릿을 생성합니다.
 */
function createNewPost(title: string): void {
  if (!title) {
    console.error("오류: 게시물 제목을 입력하세요.");
    console.log('사용법: npm run create "게시물 제목"');
    process.exit(1);
  }

  const postsDir = path.join(__dirname, "..", "posts");

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
function main(): void {
  const command = process.argv[2];

  if (command === "create") {
    createNewPost(process.argv[3]);
  } else if (process.argv.length > 2 && process.argv[2] !== "validate") {
    // 특정 파일 검증
    const filePath = path.resolve(process.argv[2]);
    if (fs.existsSync(filePath)) {
      validateSinglePost(filePath);
    } else {
      console.error(`Error: File not found: ${filePath}`);
      process.exit(1);
    }
  } else {
    // 기본: 모든 게시물 검증
    validateAllPosts();
  }
}

main();
