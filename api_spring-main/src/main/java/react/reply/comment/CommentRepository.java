package react.reply.comment;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CommentRepository extends JpaRepository<CommentEntity, Integer>{
	public Page<CommentEntity> findByParentno(int parent_no, Pageable page);
	public void deleteByParentno(int parent_no);
}
