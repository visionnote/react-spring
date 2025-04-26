package react.reply.comment;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import react.reply.user.UserEntity;
import react.reply.util.PageMaker;
import react.reply.util.PageVO;

@RestController
@RequestMapping("/api/comment")
public class CommentController {
	
	@Autowired
	private CommentRepository commentRepo;
	
	
	@GetMapping("/list")
	public PageMaker list(@RequestParam int parent_no, PageVO vo) {
		return new PageMaker(commentRepo.findByParentno(parent_no, vo.makePageable(0, "no")));
	}
	
	@PostMapping("/regist")
	public Map<String, Object> regist(@RequestBody Map map) {
		UserEntity userEntity = new UserEntity();
		userEntity.setNo((Integer)map.get("user_no"));
		
		CommentEntity commentEntity = new CommentEntity();
		commentEntity.setContent((String)map.get("content"));
		commentEntity.setParentno((Integer)map.get("parent_no"));
		commentEntity.setUser(userEntity);
		
		CommentEntity entity = commentRepo.save(commentEntity);
		Map<String, Object> result = new HashMap<>();
		result.put("entity", entity);
		result.put("result", entity == null ? "fail" : "success");
		return result;
	}
	
	@GetMapping("/delete")
	public Map delete(@RequestParam int no, PageVO vo) {
		commentRepo.deleteById(no);
		Map<String, Object> result = new HashMap<>();
		result.put("result", "success");
		return result;
	}
	
	@GetMapping("/deleteAll")
	public Map deleteAll(@RequestParam int parent_no, PageVO vo) {
		commentRepo.deleteByParentno(parent_no);
		Map<String, Object> result = new HashMap<>();
		result.put("result", "success");
		return result;
	}
}
