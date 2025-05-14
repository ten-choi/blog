declare module "front-matter" {
  interface Attributes {
    title: string;
    published?: boolean;
    description?: string;
    tags?: string;
    cover_image?: string;
    series?: string;
    [key: string]: any;
  }

  interface FrontMatterResult<T = Attributes> {
    attributes: T;
    body: string;
    frontmatter: string;
  }

  function frontMatter<T = Attributes>(content: string): FrontMatterResult<T>;

  export = frontMatter;
}
