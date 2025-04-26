package react.reply;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;

import jakarta.transaction.Transactional;
import react.reply.reply.ReplyEntity;
import react.reply.reply.ReplyRepository;

@SpringBootTest
class ReplyTest {

	@Autowired
	private ReplyRepository replyRepo;
	
	@Test
	@Transactional
	void contextLoads() {
		Page<ReplyEntity> page = replyRepo.findAll(PageRequest.of(0, 10,Sort.by(Direction.DESC,"no")));
		page.getContent().stream().forEach(r->System.out.println(r.getTitle()+","+r.getComment().size()));
		
		System.out.println(page.getContent().get(3));
	}

}
