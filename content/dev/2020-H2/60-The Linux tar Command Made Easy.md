---
title: "The Linux tar Command Made Easy"
labels: ["OS","Linux","tar","Archive"]
published: true
date: 2020-11-24T11:22:25+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 60
tistoryUrl: "https://yeolceo.tistory.com/60"
tistoryCategory: "OS/Linux"
tistoryTags: ["tar","Linux","linux","linux","tar"]
tistoryPostedAt: "2020-11-24 11:22:25"
language: en
bloggerPostId: "6218452766757088929"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/60/img.webp)

tar \[-option\]  \[filename\]

 tar -cvf aaa.tar.gz abc   Create an archive

 tar -xvf aaa.tar.gz   Extract an archive

 tar -zcvf aaa.tar.gz abc

 tar -zxvf aaa.tar.gz  

\-f Specifies the target file.

\-c Used to bundle existing files into a tar archive.

\-v Prints what the command is doing to the terminal.

\-x Used to extract an existing tar file.

Extracts files from a tar archive.

 tar \[OPTION...\] \[FILE\]... 

        -f     : Specify the target tar archive. (default option)  
        -c     : Create a tar archive, overwriting any existing one. (used for bundling files)  
        -x     : Extract files from a tar archive. (used for unpacking files)  
        -v     : List the processing details (file info) verbosely.  
        -z     : Apply gzip compression.  
        -j     : Apply bzip2 compression.  
        -t     : List the contents of a tar archive.  
        -C     : Specify the target directory path.  
        -A     : Append the given tar files to a tar archive.  
        -d     : Find differences between a tar archive and the file system.  
        -r     : Append files to the end of a tar archive.  
        -u     : Append files to the end of a tar archive (only if newer).  
        -k     : Keep existing files when extracting a tar archive.  
        -U     : Remove existing files before extracting a tar archive.  
        -w     : Ask for confirmation on every action. (interactive)  
        -e     : Stop on the first error

tar usage examples and options

<table style="border-collapse: collapse; width: 100%;" border="1"><tbody><tr><td><a href="https://recipes4dev.tistory.com/146#31-%ED%98%84%EC%9E%AC-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EC%9D%98-%EB%AA%A8%EB%93%A0-%ED%8C%8C%EC%9D%BC%EA%B3%BC-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EB%A5%BC-tar%EB%A1%9C-%EB%AC%B6%EA%B8%B0">Bundle all files and directories in the current directory into a tar archive</a></td><td>tar cvf T.tar *</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#32-%EB%8C%80%EC%83%81-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EB%A5%BC-%ED%8F%AC%ED%95%A8%ED%95%9C-%EB%AA%A8%EB%93%A0-%ED%8C%8C%EC%9D%BC%EA%B3%BC-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EB%A5%BC-tar%EB%A1%9C-%EB%AC%B6%EA%B8%B0">Bundle a target directory, including all its files and subdirectories, into a tar archive</a></td><td>tar cvf T.tar [PATH]</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#33-%ED%8C%8C%EC%9D%BC%EC%9D%84-%EC%A7%80%EC%A0%95%ED%95%98%EC%97%AC-tar-%EC%95%84%EC%B9%B4%EC%9D%B4%EB%B8%8C%EB%A1%9C-%EB%AC%B6%EA%B8%B0">Bundle specific files into a tar archive</a></td><td>tar cvf T.tar [FILE_1] [FILE_2]</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#34-tar-%EC%95%84%EC%B9%B4%EC%9D%B4%EB%B8%8C%EB%A5%BC-%ED%98%84%EC%9E%AC-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EC%97%90-%ED%92%80%EA%B8%B0">Extract a tar archive into the current directory</a></td><td>tar xvf T.tar</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#35-tar-%EC%95%84%EC%B9%B4%EC%9D%B4%EB%B8%8C%EB%A5%BC-%EC%A7%80%EC%A0%95%EB%90%9C-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EC%97%90-%ED%92%80%EA%B8%B0">Extract a tar archive into a specified directory</a></td><td>tar xvf T.tar -C [PATH]</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#36-tar-%EC%95%84%EC%B9%B4%EC%9D%B4%EB%B8%8C%EC%9D%98-%EB%82%B4%EC%9A%A9-%ED%99%95%EC%9D%B8%ED%95%98%EA%B8%B0">List the contents of a tar archive</a></td><td>tar tvf T.tar</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#37-%ED%98%84%EC%9E%AC-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EB%A5%BC-tar%EB%A1%9C-%EB%AC%B6%EA%B3%A0-gzip%EC%9C%BC%EB%A1%9C-%EC%95%95%EC%B6%95%ED%95%98%EA%B8%B0">Bundle the current directory into a tar archive and compress it with gzip</a></td><td>tar zcvf T.tar.gz *</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#38-gzip%EC%9C%BC%EB%A1%9C-%EC%95%95%EC%B6%95%EB%90%9C-tar-%EC%95%84%EC%B9%B4%EC%9D%B4%EB%B8%8C%EB%A5%BC-%ED%98%84%EC%9E%AC-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EC%97%90-%ED%92%80%EA%B8%B0">Extract a gzip-compressed tar archive into the current directory</a></td><td>tar zxvf T.tar.gz</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#39-%ED%98%84%EC%9E%AC-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EB%A5%BC-tar%EB%A1%9C-%EB%AC%B6%EA%B3%A0-bzip2%EC%9C%BC%EB%A1%9C-%EC%95%95%EC%B6%95%ED%95%98%EA%B8%B0">Bundle the current directory into a tar archive and compress it with bzip2</a></td><td>tar jcvf T.tar.bz2 *</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#310-bzip2%EB%A1%9C-%EC%95%95%EC%B6%95%EB%90%9C-tar-%EC%95%84%EC%B9%B4%EC%9D%B4%EB%B8%8C%EB%A5%BC-%ED%98%84%EC%9E%AC-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EC%97%90-%ED%92%80%EA%B8%B0">Extract a bzip2-compressed tar archive into the current directory</a></td><td>tar jxvf T.tar.bz2</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#311-tar-%EC%95%84%EC%B9%B4%EC%9D%B4%EB%B8%8C-%EB%AC%B6%EA%B1%B0%EB%82%98-%ED%92%80-%EB%95%8C-%ED%8C%8C%EC%9D%BC-%EB%B3%84-%EC%A7%84%ED%96%89-%EC%97%AC%EB%B6%80-%ED%99%95%EC%9D%B8%ED%95%98%EA%B8%B0">Show per-file progress when creating or extracting a tar archive</a></td></tr></tbody></table>

.
