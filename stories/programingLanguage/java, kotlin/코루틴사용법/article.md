![Description](https://img.notionusercontent.com/s3/prod-files-secure%2F6ab3efe6-44b5-4e5c-9d86-56543fb7f59d%2Fc3b86c80-eaba-4a31-971d-868a2b179849%2Ftest2.jpg/size/w=1420?exp=1727749267&sig=VX63E66yaxZvLTyfE2Db1fyK5g_lgajo6O10Oikoyq0)

<!-- pre image 설정해야하나 위처럼 -->

## What is the mongoDb

동시성 제어 필요성
리드하고 조회수 계속올리기때문에 
100회정도 연속으로하면 concurency가 깨질거같다
이에대해 mongodb에서의 처리법을 고민해보면
OCC (optimistic concurrency control)
PCC (pessimistic concurrency control)

위의 두가지 방향성이 있다

몽고디비에서는 아래의 방식으로 사용가능하여 진행하였다
db.collection.findAndModify
