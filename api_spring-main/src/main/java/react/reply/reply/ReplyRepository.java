package react.reply.reply;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface ReplyRepository extends JpaRepository<ReplyEntity, Integer>{
	@EntityGraph(attributePaths = {"user", "comment"})
	public Page<ReplyEntity> findByTitleContaining(String searchWord, Pageable page);
	@EntityGraph(attributePaths = {"user", "comment"})
	public Page<ReplyEntity> findByContentContaining(String searchWord, Pageable page);
	@EntityGraph(attributePaths = {"user", "comment"})
	public Page<ReplyEntity> findByTitleContainingOrContentContaining(String searchWord, String searchWord2, Pageable page);

	@EntityGraph(attributePaths = {"user", "comment"})
	public Page<ReplyEntity> findAll(Pageable pageable);

	// ono 수정
	@Modifying // update는 반드시 추가
	@Query("update ReplyEntity set ono=ono+1 where gno=?1 AND ono > ?2")
	public void updateOno(int gno, int ono);
}
